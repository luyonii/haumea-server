package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct{ C *redis.Client }

func OpenRedis(addr string) *Redis {
	return &Redis{C: redis.NewClient(&redis.Options{Addr: addr})}
}

func (r *Redis) Close() error { return r.C.Close() }

// ---- Challenges ----

func (r *Redis) PutChallenge(ctx context.Context, hwid string, nonceB64 string) error {
	return r.C.Set(ctx, "challenge:"+hwid, nonceB64, 60*time.Second).Err()
}

// TakeChallenge atomically returns and deletes the challenge nonce via GETDEL
// (Redis 6.2+); empty string + nil means absent.
func (r *Redis) TakeChallenge(ctx context.Context, hwid string) (string, error) {
	v, err := r.C.GetDel(ctx, "challenge:"+hwid).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return v, err
}

// ---- Sessions ----

type Session struct {
	LicenseID   int64     `json:"license_id"`
	HWID        string    `json:"hwid"`
	SessionKey  string    `json:"session_key_b64"`
	NextNonce   string    `json:"next_nonce_b64"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (r *Redis) PutSession(ctx context.Context, token string, s *Session, ttl time.Duration) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return r.C.Set(ctx, "session:"+token, b, ttl).Err()
}

func (r *Redis) GetSession(ctx context.Context, token string) (*Session, error) {
	v, err := r.C.Get(ctx, "session:"+token).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *Redis) RefreshSession(ctx context.Context, token string, s *Session, ttl time.Duration) error {
	return r.PutSession(ctx, token, s, ttl)
}

func (r *Redis) KillSessionsFor(ctx context.Context, licenseID int64) {
	// shortcut: we don't index sessions by license; we track "latest token per license"
	// so the previous one can be invalidated. One key per license.
	_ = r.C.Del(ctx, "session_of_license:"+itoa(licenseID)).Err()
}

func (r *Redis) RememberLatestToken(ctx context.Context, licenseID int64, token string, ttl time.Duration) error {
	return r.C.Set(ctx, "session_of_license:"+itoa(licenseID), token, ttl).Err()
}

func (r *Redis) LatestToken(ctx context.Context, licenseID int64) (string, error) {
	v, err := r.C.Get(ctx, "session_of_license:"+itoa(licenseID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return v, err
}

func (r *Redis) DeleteSession(ctx context.Context, token string) {
	_ = r.C.Del(ctx, "session:"+token).Err()
}

// TrySetOnce is SET key 1 NX EX ttl: returns true iff key did not exist.
// Used as a one-shot anti-replay guard.
func (r *Redis) TrySetOnce(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return r.C.SetNX(ctx, key, 1, ttl).Result()
}

// ---- Revocation cache ----

// SetRevoked marks a license revoked for ttl (used as a fast check before DB).
func (r *Redis) SetRevoked(ctx context.Context, licenseID int64, ttl time.Duration) error {
	return r.C.Set(ctx, "license:revoked:"+itoa(licenseID), 1, ttl).Err()
}

// IsRevoked returns true when the revoked flag is present in Redis.
func (r *Redis) IsRevoked(ctx context.Context, licenseID int64) (bool, error) {
	_, err := r.C.Get(ctx, "license:revoked:"+itoa(licenseID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ---- Rate limit ----

// Allow returns true if the per-minute counter under key is under limit. Fixed window.
func (r *Redis) Allow(ctx context.Context, key string, limit int) (bool, error) {
	n, err := r.C.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if n == 1 {
		_ = r.C.Expire(ctx, key, time.Minute).Err()
	}
	return n <= int64(limit), nil
}

// ---- small helpers ----

func itoa(n int64) string {
	// avoid strconv import in one spot — trivial manual conversion.
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
