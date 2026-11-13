package bot

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/remnawave"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

func renderTestBot(t *testing.T, panel Panel) (*Bot, *fakeAPI) {
	t.Helper()
	api := &fakeAPI{}
	operators := []config.Operator{
		{ID: 7, Role: config.RoleAdmin},
		{ID: 8, Role: config.RoleViewer},
	}
	b := newTestBot(t, api, panel, newTestStore(t), operators, nil)
	return b, api
}

func sampleNodes() []remnawave.Node {
	used, limit := int64(1536), int64(10<<30)
	changed := time.Date(2026, 11, 1, 10, 30, 0, 0, time.UTC)
	return []remnawave.Node{
		{Name: "relay-01", CountryCode: "RU", Status: remnawave.NodeStatusConnected, UsersOnline: 3},
		{Name: "exit-01", CountryCode: "FI", Status: remnawave.NodeStatusConnecting, UsersOnline: 0,
			Usage: remnawave.NodeUsage{UsedBytes: &used, LimitBytes: &limit}, LastStatusChange: &changed},
		{Name: "exit-02", Status: remnawave.NodeStatusDisabled},
		{Name: "exit-03", Status: remnawave.NodeStatusDisconnected},
	}
}

func TestHelpTextPerRole(t *testing.T) {
	b, _ := renderTestBot(t, &fakePanel{})
	for role, want := range map[config.Role]string{
		config.RoleViewer: "Роль: viewer.",
		config.RoleAdmin:  "Роль: admin.",
	} {
		got := b.command(context.Background(), role, "/help")
		if !strings.Contains(got, want) {
			t.Errorf("%s help = %q, want %q", role, got, want)
		}
		for _, cmd := range []string{"/help", "/status", "/nodes", "/users", "/user <id>"} {
			if !strings.Contains(got, cmd) {
				t.Errorf("%s help does not mention %s", role, cmd)
			}
		}
	}
}

func TestCommandParsingAndStrictArguments(t *testing.T) {
	panel := &fakePanel{user: remnawave.User{ID: 42, Username: "alice", Status: remnawave.UserStatusActive}}
	b, _ := renderTestBot(t, panel)
	tests := map[string]string{
		"/status extra":              "Использование: /status",
		"/nodes x":                   "Использование: /nodes",
		"/users all":                 "Использование: /users",
		"/help now":                  "Использование: /help",
		"/user":                      userUsage,
		"/user abc":                  userUsage,
		"/user 0":                    userUsage,
		"/user -5":                   userUsage,
		"/user 1 2":                  userUsage,
		"/user 99999999999999999999": userUsage,
		"/unknown":                   "Неизвестная команда. Используйте /help.",
		"/":                          "Неизвестная команда. Используйте /help.",
		"hello":                      "Неизвестная команда. Используйте /help.",
	}
	for input, want := range tests {
		if got := b.command(context.Background(), config.RoleViewer, input); got != want {
			t.Errorf("command(%q) = %q, want %q", input, got, want)
		}
	}
	got := b.command(context.Background(), config.RoleViewer, "/user 42")
	if !strings.Contains(got, "Пользователь 42") {
		t.Errorf("/user 42 = %q", got)
	}
	if len(panel.userCalls) != 1 || panel.userCalls[0] != 42 {
		t.Errorf("panel user calls = %v", panel.userCalls)
	}
	if got := b.command(context.Background(), config.RoleViewer, "/help@vpn_bot"); !strings.Contains(got, "Роль: viewer.") {
		t.Errorf("/help@vpn_bot = %q", got)
	}
}

func TestUnknownCommandDoesNotEchoArguments(t *testing.T) {
	b, _ := renderTestBot(t, &fakePanel{})
	for _, input := range []string{"/status SECRET-VALUE", "/unknown SECRET-VALUE", "SECRET-VALUE"} {
		got := b.command(context.Background(), config.RoleViewer, input)
		if strings.Contains(got, "SECRET-VALUE") {
			t.Errorf("reply to %q echoes the argument: %q", input, got)
		}
	}
}

func TestStatusSummary(t *testing.T) {
	b, _ := renderTestBot(t, &fakePanel{nodes: sampleNodes()})
	got := b.status(context.Background())
	for _, want := range []string{
		"Панель: доступна",
		"Узлы: 4",
		"connected: 1, connecting: 1, disconnected: 1, disabled: 1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status = %q, missing %q", got, want)
		}
	}
}

func TestPanelErrorsAreConcise(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"401", &remnawave.APIError{StatusCode: 401}, "ошибка авторизации (401)"},
		{"403", &remnawave.APIError{StatusCode: 403}, "доступ запрещён (403)"},
		{"404", &remnawave.APIError{StatusCode: 404}, "не найдено (404)"},
		{"429", &remnawave.APIError{StatusCode: 429}, "превышен лимит запросов (429)"},
		{"500", &remnawave.APIError{StatusCode: 502}, "ошибка сервера (5xx)"},
		{"malformed", remnawave.ErrMalformedResponse, "некорректный ответ панели"},
		{"timeout", context.DeadlineExceeded, "таймаут"},
		{"transport", errors.New("SECRET-BODY"), "недоступна"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := renderTestBot(t, &fakePanel{nodesErr: tt.err, usersErr: tt.err, userErr: tt.err})
			for name, got := range map[string]string{
				"status": b.status(context.Background()),
				"nodes":  b.nodes(context.Background()),
				"users":  b.users(context.Background()),
				"user":   b.user(context.Background(), 42),
			} {
				if !strings.Contains(got, tt.want) {
					t.Errorf("%s = %q, want %q", name, got, tt.want)
				}
				if strings.Contains(got, "SECRET-BODY") {
					t.Errorf("%s leaks the underlying error: %q", name, got)
				}
			}
		})
	}
}

func TestNodesOutputIsBoundedAndOmitsUUIDs(t *testing.T) {
	nodes := make([]remnawave.Node, 100)
	for i := range nodes {
		nodes[i] = remnawave.Node{
			UUID:        fmt.Sprintf("uuid-secret-%03d", i),
			Name:        fmt.Sprintf("node-%03d", 99-i),
			CountryCode: "FI",
			Status:      remnawave.NodeStatusConnected,
		}
	}
	b, _ := renderTestBot(t, &fakePanel{nodes: nodes})
	got := b.nodes(context.Background())
	lines := strings.Split(got, "\n")
	if len(lines) != 1+maxNodeLines+1 {
		t.Errorf("nodes output has %d lines, want %d", len(lines), 1+maxNodeLines+1)
	}
	if !strings.Contains(got, "Узлы: 100") || !strings.Contains(got, "… ещё 80 узлов") {
		t.Errorf("nodes header or remainder = %q", got)
	}
	if strings.Contains(got, "uuid-secret") {
		t.Error("nodes output contains a node UUID")
	}
	if !strings.Contains(lines[1], "node-000") {
		t.Errorf("nodes are not sorted by name: %q", lines[1])
	}
}

func TestUsersReportsBoundedPageAndTotal(t *testing.T) {
	users := make([]remnawave.User, 100)
	statuses := []remnawave.UserStatus{
		remnawave.UserStatusActive,
		remnawave.UserStatusDisabled,
		remnawave.UserStatusLimited,
		remnawave.UserStatusExpired,
	}
	for i := range users {
		users[i] = remnawave.User{ID: int64(i + 1), Username: fmt.Sprintf("user-%d", i+1), Status: statuses[i%4]}
	}
	panel := &fakePanel{page: remnawave.UsersPage{Users: users, Total: 1234}}
	b, _ := renderTestBot(t, panel)
	got := b.users(context.Background())
	for _, want := range []string{
		"всего 1234",
		"на странице 100 (смещение 0)",
		"ACTIVE: 25, DISABLED: 25, LIMITED: 25, EXPIRED: 25",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("users = %q, missing %q", got, want)
		}
	}
	if len(panel.usersCalls) != 1 || panel.usersCalls[0].start != 0 || panel.usersCalls[0].size != usersPage {
		t.Errorf("panel ListUsers calls = %+v", panel.usersCalls)
	}

	b, _ = renderTestBot(t, &fakePanel{page: remnawave.UsersPage{}})
	if got := b.users(context.Background()); got != "Пользователи: нет" {
		t.Errorf("empty users = %q", got)
	}
}

func TestUserFieldsAndSanitization(t *testing.T) {
	online := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	u := remnawave.User{
		ID:       42,
		Username: "alice\nops",
		Status:   remnawave.UserStatusActive,
		ExpireAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Usage: remnawave.UserUsage{
			UsedBytes:         1536,
			LifetimeUsedBytes: 2048,
			LimitBytes:        10 << 30,
		},
		OnlineAt: &online,
	}
	b, _ := renderTestBot(t, &fakePanel{user: u})
	got := b.user(context.Background(), 42)
	for _, want := range []string{
		"Пользователь 42: alice ops",
		"Статус: ACTIVE",
		"Трафик: 1.5 KiB / 10.0 GiB",
		"За всё время: 2.0 KiB",
		"Онлайн: 2026-11-13 10:00 UTC",
		"Первый вход: нет данных",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("user = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "2027") {
		t.Errorf("user output includes the out-of-scope expiry time: %q", got)
	}
	if strings.Contains(got, "\nops") {
		t.Errorf("user name was not sanitized: %q", got)
	}
}

func TestSendTruncatesReply(t *testing.T) {
	b, api := renderTestBot(t, &fakePanel{})
	long := strings.Repeat("a", telegram.MaxMessageUnits+500)
	if err := b.send(context.Background(), 7, long); err != nil {
		t.Fatalf("send: %v", err)
	}
	sent := api.sentReplies()
	if len(sent) != 1 {
		t.Fatalf("sent %d replies", len(sent))
	}
	if n := telegram.UTF16Length(sent[0].text); n > telegram.MaxMessageUnits {
		t.Errorf("reply has %d UTF-16 units", n)
	}
	if !strings.HasSuffix(sent[0].text, telegram.TruncationMarker) {
		t.Error("long reply has no truncation marker")
	}
	if err := b.send(context.Background(), 7, ""); err != nil {
		t.Fatalf("empty send: %v", err)
	}
	if got := len(api.sentReplies()); got != 1 {
		t.Errorf("empty reply was sent (%d replies)", got)
	}
}

func TestHandleAppliesAllowlistAndRoles(t *testing.T) {
	b, api := renderTestBot(t, &fakePanel{})
	ctx := context.Background()
	if err := b.handle(ctx, privateMessage(1, 7, 7, "/help")); err != nil {
		t.Fatal(err)
	}
	if err := b.handle(ctx, privateMessage(2, 8, 8, "/help")); err != nil {
		t.Fatal(err)
	}
	if err := b.handle(ctx, privateMessage(3, 9, 9, "/help")); err != nil {
		t.Fatal(err)
	}
	group := telegram.Update{ID: 4, Message: &telegram.Message{
		From: &telegram.User{ID: 7},
		Chat: &telegram.Chat{ID: -100, Type: telegram.ChatGroup},
		Text: "/help",
	}}
	if err := b.handle(ctx, group); err != nil {
		t.Fatal(err)
	}
	sent := api.sentReplies()
	if len(sent) != 2 {
		t.Fatalf("replies = %d, want 2", len(sent))
	}
	if !strings.Contains(sent[0].text, "Роль: admin.") || !strings.Contains(sent[1].text, "Роль: viewer.") {
		t.Errorf("role replies = %q, %q", sent[0].text, sent[1].text)
	}
	if b.ignored != 2 {
		t.Errorf("ignored = %d, want 2", b.ignored)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := map[int64]string{
		0:               "0 B",
		1023:            "1023 B",
		1024:            "1.0 KiB",
		1536:            "1.5 KiB",
		10 << 30:        "10.0 GiB",
		1 << 40:         "1.0 TiB",
		1<<40 + 512<<30: "1.5 TiB",
	}
	for n, want := range tests {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestCleanField(t *testing.T) {
	tests := map[string]string{
		"  normal  ":  "normal",
		"line\nbreak": "line break",
		"tab\there":   "tab here",
		"\x00\x01":    "",
	}
	for in, want := range tests {
		if got := cleanField(in, 64); got != want {
			t.Errorf("cleanField(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanField(strings.Repeat("a", 100), 10); got != strings.Repeat("a", 10) {
		t.Errorf("cleanField cap = %q", got)
	}
}
