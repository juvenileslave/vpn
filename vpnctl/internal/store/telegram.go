package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

// maxClaimedUpdates bounds the number of processed Telegram update IDs kept
// for duplicate suppression. Older IDs cannot be returned by getUpdates once
// the persisted offset has advanced past them.
const maxClaimedUpdates = 1024

// BotOffset returns the offset to pass to getUpdates, or 0 when the bot has
// not processed an update yet.
func (s *Store) BotOffset(ctx context.Context) (int64, error) {
	var offset int64
	err := s.db.QueryRowContext(ctx,
		`SELECT update_offset FROM telegram_offsets WHERE id = 1`).Scan(&offset)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, dbError("read bot offset", err)
	}
	if offset < 0 {
		return 0, fmt.Errorf("%w: bot offset row", ErrCorrupt)
	}
	return offset, nil
}

// ClaimBotUpdate records updateID as processed and advances the bot offset to
// updateID+1 if that is larger. It returns false, without changing anything,
// when updateID was already claimed. The insert, the monotonic offset update
// and the retention prune run in one BEGIN IMMEDIATE transaction, so two bot
// processes sharing the database claim each update at most once and never
// move the offset backwards.
func (s *Store) ClaimBotUpdate(ctx context.Context, updateID int64) (bool, error) {
	if updateID < 1 || updateID == math.MaxInt64 {
		return false, invalid("Telegram update ID must be positive and leave room for an offset")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, dbError("begin bot update claim", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO telegram_updates (update_id) VALUES (?)
		 ON CONFLICT (update_id) DO NOTHING`, updateID)
	if err != nil {
		return false, dbError("claim bot update", err)
	}
	claimed, err := res.RowsAffected()
	if err != nil {
		return false, dbError("claim bot update", err)
	}
	if claimed == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telegram_offsets (id, update_offset) VALUES (1, ?)
		 ON CONFLICT (id) DO UPDATE SET update_offset = max(update_offset, excluded.update_offset)`,
		updateID+1); err != nil {
		return false, dbError("advance bot offset", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM telegram_updates
		 WHERE update_id NOT IN (
			SELECT update_id FROM telegram_updates ORDER BY update_id DESC LIMIT ?
		 )`, maxClaimedUpdates); err != nil {
		return false, dbError("prune bot updates", err)
	}
	if err := tx.Commit(); err != nil {
		return false, dbError("commit bot update claim", err)
	}
	return true, nil
}
