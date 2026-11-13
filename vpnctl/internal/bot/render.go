package bot

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
)

func (b *Bot) status(ctx context.Context) string {
	nodes, err := b.listNodes(ctx)
	if err != nil {
		return "Панель: " + panelFailure(err)
	}
	var connected, connecting, disconnected, disabled int
	for _, n := range nodes {
		switch n.Status {
		case remnawave.NodeStatusConnected:
			connected++
		case remnawave.NodeStatusConnecting:
			connecting++
		case remnawave.NodeStatusDisabled:
			disabled++
		default:
			disconnected++
		}
	}
	return fmt.Sprintf("Панель: доступна\nУзлы: %d\nconnected: %d, connecting: %d, disconnected: %d, disabled: %d",
		len(nodes), connected, connecting, disconnected, disabled)
}

func (b *Bot) nodes(ctx context.Context) string {
	nodes, err := b.listNodes(ctx)
	if err != nil {
		return "Панель: " + panelFailure(err)
	}
	if len(nodes) == 0 {
		return "Узлы: нет"
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	shown := min(len(nodes), maxNodeLines)
	lines := make([]string, 0, shown+2)
	lines = append(lines, "Узлы: "+strconv.Itoa(len(nodes)))
	for i := range shown {
		lines = append(lines, formatNode(nodes[i]))
	}
	if len(nodes) > shown {
		lines = append(lines, fmt.Sprintf("… ещё %d узлов", len(nodes)-shown))
	}
	return strings.Join(lines, "\n")
}

func formatNode(n remnawave.Node) string {
	var b strings.Builder
	b.WriteString("- ")
	name := cleanField(n.Name, 64)
	if name == "" {
		name = "—"
	}
	b.WriteString(name)
	if country := cleanField(n.CountryCode, 8); country != "" {
		b.WriteString(" [" + country + "]")
	}
	b.WriteString(": ")
	b.WriteString(cleanField(string(n.Status), 32))
	b.WriteString("; онлайн ")
	b.WriteString(strconv.FormatInt(n.UsersOnline, 10))
	if n.Usage.UsedBytes != nil {
		b.WriteString("; трафик ")
		b.WriteString(formatBytes(*n.Usage.UsedBytes))
		if n.Usage.LimitBytes != nil && *n.Usage.LimitBytes > 0 {
			b.WriteString(" / ")
			b.WriteString(formatBytes(*n.Usage.LimitBytes))
		}
	}
	if n.LastStatusChange != nil && !n.LastStatusChange.IsZero() {
		b.WriteString("; изменение ")
		b.WriteString(formatTime(*n.LastStatusChange))
	}
	return b.String()
}

func (b *Bot) users(ctx context.Context) string {
	page, err := b.listUsers(ctx, 0, usersPage)
	if err != nil {
		return "Панель: " + panelFailure(err)
	}
	if page.Total == 0 && len(page.Users) == 0 {
		return "Пользователи: нет"
	}
	counts := make(map[remnawave.UserStatus]int, 4)
	unknown := 0
	for _, u := range page.Users {
		if u.Status.Known() {
			counts[u.Status]++
		} else {
			unknown++
		}
	}
	parts := []string{
		"ACTIVE: " + strconv.Itoa(counts[remnawave.UserStatusActive]),
		"DISABLED: " + strconv.Itoa(counts[remnawave.UserStatusDisabled]),
		"LIMITED: " + strconv.Itoa(counts[remnawave.UserStatusLimited]),
		"EXPIRED: " + strconv.Itoa(counts[remnawave.UserStatusExpired]),
	}
	if unknown > 0 {
		parts = append(parts, "неизвестно: "+strconv.Itoa(unknown))
	}
	return fmt.Sprintf("Пользователи: всего %d; на странице %d (смещение 0)\n%s",
		page.Total, len(page.Users), strings.Join(parts, ", "))
}

func (b *Bot) user(ctx context.Context, id int64) string {
	u, err := b.getUser(ctx, id)
	if err != nil {
		return "Панель: " + panelFailure(err)
	}
	username := cleanField(u.Username, 64)
	if username == "" {
		username = "—"
	}
	traffic := "Трафик: " + formatBytes(u.Usage.UsedBytes)
	if u.Usage.LimitBytes > 0 {
		traffic += " / " + formatBytes(u.Usage.LimitBytes)
	} else {
		traffic += " (без лимита)"
	}
	lines := []string{
		fmt.Sprintf("Пользователь %d: %s", u.ID, username),
		"Статус: " + cleanField(string(u.Status), 32),
		traffic,
	}
	if u.Usage.LifetimeUsedBytes > 0 {
		lines = append(lines, "За всё время: "+formatBytes(u.Usage.LifetimeUsedBytes))
	}
	lines = append(lines,
		"Онлайн: "+formatOptionalTime(u.OnlineAt),
		"Первый вход: "+formatOptionalTime(u.FirstConnectedAt),
	)
	return strings.Join(lines, "\n")
}

func (b *Bot) listNodes(ctx context.Context) ([]remnawave.Node, error) {
	callCtx, cancel := context.WithTimeout(ctx, b.panelTimeout)
	defer cancel()
	return b.panel.ListNodes(callCtx)
}

func (b *Bot) listUsers(ctx context.Context, start, size int) (remnawave.UsersPage, error) {
	callCtx, cancel := context.WithTimeout(ctx, b.panelTimeout)
	defer cancel()
	return b.panel.ListUsers(callCtx, start, size)
}

func (b *Bot) getUser(ctx context.Context, id int64) (remnawave.User, error) {
	callCtx, cancel := context.WithTimeout(ctx, b.panelTimeout)
	defer cancel()
	return b.panel.User(callCtx, id)
}

// panelFailure describes a panel error without repeating a response body,
// code, message or URL.
func panelFailure(err error) string {
	var apiErr *remnawave.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.StatusCode == 401:
			return "ошибка авторизации (401)"
		case apiErr.StatusCode == 403:
			return "доступ запрещён (403)"
		case apiErr.StatusCode == 404:
			return "не найдено (404)"
		case apiErr.StatusCode == 429:
			return "превышен лимит запросов (429)"
		case apiErr.StatusCode >= 500:
			return "ошибка сервера (5xx)"
		default:
			return fmt.Sprintf("ошибка панели (%d)", apiErr.StatusCode)
		}
	}
	switch {
	case errors.Is(err, remnawave.ErrMalformedResponse):
		return "некорректный ответ панели"
	case errors.Is(err, context.DeadlineExceeded):
		return "таймаут"
	case errors.Is(err, context.Canceled):
		return "запрос отменён"
	default:
		return "недоступна"
	}
}

func cleanField(s string, maxRunes int) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxRunes {
			break
		}
		if r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029 {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

func formatBytes(n int64) string {
	if n < 0 {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := [...]string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	value := float64(n)
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return strconv.FormatInt(n, 10) + " B"
	}
	return fmt.Sprintf("%.1f %s", value, units[unit])
}

func formatOptionalTime(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "нет данных"
	}
	return formatTime(*t)
}

func formatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04 UTC")
}
