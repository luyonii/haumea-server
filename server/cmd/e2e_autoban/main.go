// Drives the server-primary auto-ban E2E against a running secblind server.
// Not part of the shipped binary; built ad-hoc for staging verification.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/secblind/server/pkg/crypto"
)

func main() {
	base := flag.String("base", "http://127.0.0.1:8080", "server base URL")
	key := flag.String("key", "", "license key")
	flag.Parse()
	if *key == "" {
		fmt.Fprintln(os.Stderr, "need -key")
		os.Exit(2)
	}

	hwidRaw := sha256.Sum256([]byte("e2e-autoban-test-hwid-2026-11-23"))
	hwid := hex.EncodeToString(hwidRaw[:])
	fmt.Printf("hwid=%s\n", hwid)

	ch := post(*base+"/api/v1/auth/challenge", map[string]any{"hwid": hwid})
	nonceB64 := ch["challenge"].(string)
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	must(err, "decode challenge")

	salt := append([]byte(hwid), crypto.HKDFSalt...)
	derived, err := crypto.HKDF([]byte(*key), salt, nil, 32)
	must(err, "hkdf")
	mac := crypto.HMAC256(derived, nonce)

	login := post(*base+"/api/v1/auth/login", map[string]any{
		"license_key":        *key,
		"hwid":               hwid,
		"challenge":          nonceB64,
		"challenge_response": base64.StdEncoding.EncodeToString(mac),
	})
	token := login["session_token"].(string)
	sessionKey, err := base64.StdEncoding.DecodeString(login["session_key"].(string))
	must(err, "decode session_key")
	nextNonce := login["next_nonce"].(string)

	kHB, err := crypto.HKDFExpand(sessionKey, crypto.InfoHeartbeat, 32)
	must(err, "hkdf expand")

	hb := func(sMask, tMask uint32, nonceIn string) map[string]any {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		canon := ts + "|" + strconv.FormatUint(uint64(sMask), 10) + "|" + strconv.FormatUint(uint64(tMask), 10)
		h := crypto.HMAC256(kHB, []byte(canon))
		return post(*base+"/api/v1/session/heartbeat", map[string]any{
			"session_token": token,
			"hmac":          base64.StdEncoding.EncodeToString(h),
			"timestamp":     ts,
			"next_nonce":    nonceIn,
			"sentinel_mask": sMask,
			"tool_mask":     tMask,
		})
	}

	r1 := hb(0x1, 0, nextNonce)
	fmt.Printf("hb1 -> %+v\n", r1)

	nextNonce, _ = r1["next_nonce"].(string)
	time.Sleep(500 * time.Millisecond)

	// second heartbeat tries the next_nonce from r1; on auto-ban the first hb
	// may have already killed the session (depending on when LogAbuse flushes),
	// in which case we expect session_expired instead of kill:true.
	r2 := hb(0x1, 0, nextNonce)
	fmt.Printf("hb2 -> %+v\n", r2)
}

func post(url string, body any) map[string]any {
	b, err := json.Marshal(body)
	must(err, "marshal")
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	must(err, "post "+url)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal %q: %v\n", string(data), err)
		os.Exit(1)
	}
	if resp.StatusCode >= 300 {
		fmt.Fprintf(os.Stderr, "HTTP %d on %s: %s\n", resp.StatusCode, url, string(data))
		os.Exit(1)
	}
	return out
}

func must(err error, where string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", where, err)
		os.Exit(1)
	}
}
