package store

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Logf is the sink the store package uses for background failures. main.go
// overrides it with the zap sugar logger; default is a no-op so tests stay quiet.
var Logf = func(string, ...any) {}

// ErrNotFound is returned when a license or payload does not exist.
var ErrNotFound = errors.New("not found")

// ErrHWIDCooldown is returned by HWIDBindIfAllowed when a rebind is blocked by the cooldown window.
var ErrHWIDCooldown = errors.New("hwid cooldown")

type License struct {
	ID     int64
	Key    string
	Banned bool
	// TargetExePath is the host executable the client should launch and inject
	// into. Empty when no per-license override exists; the client then falls
	// back to its argv[1]. Column `target_exe_path` is nullable; a NULL row
	// maps to "".
	TargetExePath string
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

// LicenseStatus is the shape returned by the admin GET /license/{key} endpoint.
// Nil time fields mean the condition is not set (no revoke, no hwid bind, etc.).
type LicenseStatus struct {
	ID        int64
	Key       string
	Banned    bool
	Revoked   bool
	RevokedAt *time.Time
	HWID      *string
	BoundAt   *time.Time
	Killed    bool
	CreatedAt time.Time
	Note      *string
}

// InsertLicense creates a new license row. Returns the new id + created_at.
// On license_key uniqueness violation (SQLSTATE 23505) the caller can retry.
func (p *PG) InsertLicense(ctx context.Context, key string, note *string) (int64, time.Time, error) {
	var id int64
	var createdAt time.Time
	err := p.Pool.QueryRow(ctx,
		`INSERT INTO licenses (license_key, note) VALUES ($1, $2)
		 RETURNING id, created_at`, key, note,
	).Scan(&id, &createdAt)
	return id, createdAt, err
}

// ListLicenses returns up to `limit` licenses ordered by created_at DESC. It
// joins the same tables as LicenseStatusByKey so the shape matches, giving
// the admin dashboard a scannable row set without a second round trip per
// license. The limit is clamped by the caller (admin.go caps it at 500).
func (p *PG) ListLicenses(ctx context.Context, limit int) ([]LicenseStatus, error) {
	rows, err := p.Pool.Query(ctx,
		`SELECT l.id, l.license_key, l.banned, l.revoked_at, l.created_at, l.note,
		        b.hwid, b.bound_at, k.license_id IS NOT NULL
		   FROM licenses l
		   LEFT JOIN hwid_binds b   ON b.license_id = l.id
		   LEFT JOIN license_kill k ON k.license_id = l.id
		  ORDER BY l.created_at DESC
		  LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LicenseStatus
	for rows.Next() {
		var s LicenseStatus
		if err := rows.Scan(&s.ID, &s.Key, &s.Banned, &s.RevokedAt, &s.CreatedAt, &s.Note,
			&s.HWID, &s.BoundAt, &s.Killed); err != nil {
			return nil, err
		}
		s.Revoked = s.RevokedAt != nil
		out = append(out, s)
	}
	return out, rows.Err()
}

// LicenseStatusByKey returns a joined status snapshot for admin inspection.
func (p *PG) LicenseStatusByKey(ctx context.Context, key string) (*LicenseStatus, error) {
	var s LicenseStatus
	err := p.Pool.QueryRow(ctx,
		`SELECT l.id, l.license_key, l.banned, l.revoked_at, l.created_at, l.note,
		        b.hwid, b.bound_at, k.license_id IS NOT NULL
		   FROM licenses l
		   LEFT JOIN hwid_binds b   ON b.license_id = l.id
		   LEFT JOIN license_kill k ON k.license_id = l.id
		  WHERE l.license_key = $1`, key,
	).Scan(&s.ID, &s.Key, &s.Banned, &s.RevokedAt, &s.CreatedAt, &s.Note,
		&s.HWID, &s.BoundAt, &s.Killed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s.Revoked = s.RevokedAt != nil
	return &s, nil
}

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

// AutoBanIfSentinelThreshold bans the license iff it has >= threshold
// sentinel_trip abuse_log rows inside `window` AND is not already banned. It
// returns banned=true ONLY on the call that flips banned false->true: the
// UPDATE ... WHERE banned=false ... RETURNING id is the single source of truth
// for idempotency, so two near-simultaneous callers that both meet the
// threshold see exactly one true (the row-writer) and one (false, nil) on the
// loser — no double metric increment. pgx.ErrNoRows means either the threshold
// was not met or the license was already banned; both return (false, nil).
//
// Note: the trip timestamp column is abuse_log.occurred_at (see migration
// 0001); make_interval(secs => $3) keeps the window parameterized without
// string interpolation into the SQL.
func (p *PG) AutoBanIfSentinelThreshold(ctx context.Context, licenseID int64, threshold int, window time.Duration) (bool, error) {
	var id int64
	err := p.Pool.QueryRow(ctx,
		`WITH recent AS (
		    SELECT 1 FROM abuse_log
		     WHERE license_id = $1
		       AND reason LIKE 'sentinel_trip:%'
		       AND occurred_at > now() - make_interval(secs => $3)
		     LIMIT $2
		 ), threshold_met AS (
		    SELECT 1 FROM recent HAVING count(*) >= $2
		 )
		 UPDATE licenses
		    SET banned = true
		  WHERE id = $1
		    AND banned = false
		    AND EXISTS (SELECT 1 FROM threshold_met)
		 RETURNING id`,
		licenseID, threshold, window.Seconds(),
	).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
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

// RevokeLicense sets licenses.revoked_at = now() if not already set.
// Idempotent: a second revoke is a no-op.
func (p *PG) RevokeLicense(ctx context.Context, licenseID int64) error {
	_, err := p.Pool.Exec(ctx,
		`UPDATE licenses SET revoked_at = now()
		   WHERE id = $1 AND revoked_at IS NULL`, licenseID)
	return err
}

// IsRevoked returns true when licenses.revoked_at IS NOT NULL.
func (p *PG) IsRevoked(ctx context.Context, licenseID int64) (bool, error) {
	var hasRevoke bool
	err := p.Pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM licenses WHERE id = $1`, licenseID,
	).Scan(&hasRevoke)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return hasRevoke, err
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
	// Invalid/empty ip (e.g. spoofed X-Forwarded-For) -> NULL; a bad ::inet cast would fail the INSERT and evade audit.
	var ipArg any
	if parsed := net.ParseIP(ip); parsed != nil {
		ipArg = parsed.String()
	}
	if _, err := p.Pool.Exec(ctx,
		`INSERT INTO abuse_log (license_id, ip, reason) VALUES ($1, $2, $3)`,
		licenseID, ipArg, reason); err != nil {
		Logf("abuse log failed: %v", err)
	}
}
