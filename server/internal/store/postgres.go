package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a license or payload does not exist.
var ErrNotFound = errors.New("not found")

// ErrHWIDCooldown is returned by HWIDBindIfAllowed when a rebind is blocked by the cooldown window.
var ErrHWIDCooldown = errors.New("hwid cooldown")

type License struct {
	ID     int64
	Key    string
	Banned bool
}

type PG struct{ Pool *pgxpool.Pool }

func OpenPG(ctx context.Context, dsn string) (*PG, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &PG{Pool: pool}, nil
}

func (p *PG) Close() { p.Pool.Close() }

func (p *PG) LicenseByKey(ctx context.Context, key string) (*License, error) {
	var l License
	err := p.Pool.QueryRow(ctx,
		`SELECT id, license_key, banned FROM licenses WHERE license_key = $1`, key,
	).Scan(&l.ID, &l.Key, &l.Banned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// HWIDBindIfAllowed atomically binds hwid to licenseID under the cooldown rule:
// if a different hwid is already bound and last_change < cooldown, returns ErrHWIDCooldown;
// same hwid is a no-op. Concurrent callers for the same license serialize on the
// licenses row (SELECT ... FOR UPDATE), so the read-check-write is a single critical section.
func (p *PG) HWIDBindIfAllowed(ctx context.Context, licenseID int64, hwid string, cooldown time.Duration) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var one int
	if err := tx.QueryRow(ctx,
		`SELECT 1 FROM licenses WHERE id = $1 FOR UPDATE`, licenseID,
	).Scan(&one); err != nil {
		return err
	}

	var cur string
	err = tx.QueryRow(ctx,
		`SELECT hwid FROM hwid_binds WHERE license_id = $1`, licenseID,
	).Scan(&cur)
	hasBind := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if hasBind && cur == hwid {
		return tx.Commit(ctx)
	}
	if hasBind {
		var last time.Time
		err = tx.QueryRow(ctx,
			`SELECT last_change FROM hwid_cooldown WHERE license_id = $1`, licenseID,
		).Scan(&last)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && time.Since(last) < cooldown {
			return ErrHWIDCooldown
		}
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO hwid_binds (license_id, hwid) VALUES ($1, $2)
		 ON CONFLICT (license_id) DO UPDATE SET hwid = EXCLUDED.hwid, bound_at = now()`,
		licenseID, hwid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO hwid_cooldown (license_id, last_change) VALUES ($1, now())
		 ON CONFLICT (license_id) DO UPDATE SET last_change = now()`,
		licenseID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// LatestPayload returns the most recent PE build for the license, or ErrNotFound.
func (p *PG) LatestPayload(ctx context.Context, licenseID int64) ([]byte, error) {
	var pe []byte
	err := p.Pool.QueryRow(ctx,
		`SELECT pe_bytes FROM payload_builds
		 WHERE license_id = $1 ORDER BY updated_at DESC LIMIT 1`, licenseID,
	).Scan(&pe)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return pe, err
}

// KillStatus reports whether the license is killed.
func (p *PG) KillStatus(ctx context.Context, licenseID int64) (bool, error) {
	var one int
	err := p.Pool.QueryRow(ctx,
		`SELECT 1 FROM license_kill WHERE license_id = $1`, licenseID,
	).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (p *PG) LogAbuse(_ context.Context, licenseID *int64, ip, reason string) {
	// Detached context: the request ctx may already be cancelled (we log on 401).
	// Fire and forget; a logging failure must not break auth.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = p.Pool.Exec(ctx,
		`INSERT INTO abuse_log (license_id, ip, reason) VALUES ($1, NULLIF($2,'')::inet, $3)`,
		licenseID, ip, reason)
}
