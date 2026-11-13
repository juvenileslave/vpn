package bot

import (
	"context"
	"strconv"
	"strings"

	"github.com/juvenileslave/vpn/vpnctl/internal/config"
	"github.com/juvenileslave/vpn/vpnctl/internal/telegram"
)

// handle answers one claimed update. A malformed update, an unknown sender or
// a disallowed chat produces no message; the update is already consumed.
func (b *Bot) handle(ctx context.Context, update telegram.Update) error {
	msg := update.Message
	switch {
	case msg == nil || msg.From == nil || msg.Chat == nil || msg.From.IsBot:
		b.ignore("malformed")
		return nil
	case msg.Text == "":
		b.ignore("not a text message")
		return nil
	}
	role, ok := b.operators[msg.From.ID]
	if !ok {
		b.ignore("sender is not allowlisted")
		return nil
	}
	if msg.Chat.Type != telegram.ChatPrivate && !b.chats[msg.Chat.ID] {
		b.ignore("chat is not allowed")
		return nil
	}
	reply := b.command(ctx, role, msg.Text)
	return b.send(ctx, msg.Chat.ID, reply)
}

func (b *Bot) ignore(reason string) {
	b.ignored++
	b.log.Debug("telegram update ignored", "reason", reason)
}

// command renders one command. It never echoes arguments or message text.
func (b *Bot) command(ctx context.Context, role config.Role, text string) string {
	name, args := parseCommand(text)
	switch name {
	case "help":
		if len(args) != 0 {
			return helpUsage
		}
		return helpText(role)
	case "status":
		if len(args) != 0 {
			return "Использование: /status"
		}
		return b.status(ctx)
	case "nodes":
		if len(args) != 0 {
			return "Использование: /nodes"
		}
		return b.nodes(ctx)
	case "users":
		if len(args) != 0 {
			return "Использование: /users"
		}
		return b.users(ctx)
	case "user":
		if len(args) != 1 {
			return userUsage
		}
		id, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil || id <= 0 {
			return userUsage
		}
		return b.user(ctx, id)
	default:
		return "Неизвестная команда. Используйте /help."
	}
}

func parseCommand(text string) (string, []string) {
	fields := strings.Fields(text)
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return "", nil
	}
	name := strings.TrimPrefix(fields[0], "/")
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	return strings.ToLower(name), fields[1:]
}

const helpUsage = "Использование: /help"

const userUsage = "Использование: /user <id>"

func helpText(role config.Role) string {
	return "vpnctl bot — доступ только на чтение.\n" +
		"/help — эта справка\n" +
		"/status — доступность панели и сводка узлов\n" +
		"/nodes — список узлов\n" +
		"/users — число пользователей и статусы текущей страницы\n" +
		"/user <id> — пользователь по числовому ID\n" +
		"Роль: " + string(role) + "."
}
