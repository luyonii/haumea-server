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

// HWIDBind returns the current bound hwid for the license, or ErrNotFound.
func (p *PG) HWIDBind(ctx context.Context, licenseID int64) (string, error) {
	var h string
	err := p.Pool.QueryRow(ctx,
		`SELECT hwid FROM hwid_binds WHERE license_id = $1`, licenseID,
	).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// HWIDLastChange returns the last_change timestamp for the cooldown row, or zero.
func (p *PG) HWIDLastChange(ctx context.Context, licenseID int64) (time.Time, error) {
	var t time.Time
	err := p.Pool.QueryRow(ctx,
		`SELECT last_change FROM hwid_cooldown WHERE license_id = $1`, licenseID,
	).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	return t, err
}

// HWIDUpsertBind inserts or replaces the bind row and sets cooldown.last_change = now().
func (p *PG) HWIDUpsertBind(ctx context.Context, licenseID int64, hwid string) error {
	tx, err := p.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
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
