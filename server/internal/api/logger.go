package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogConfig controls zap/lumberjack initialization.
type LogConfig struct {
	Dev         bool   // true: console encoder + debug level
	File        string // lumberjack target; empty = stderr only
	MaxSizeMB   int
	MaxBackups  int
	MaxAgeDays  int
	Compress    bool
}

// slog is the package-level sugared logger. Loaded atomically because
// handler goroutines read it unlocked.
var slog atomic.Pointer[zap.SugaredLogger]

// SetLogger installs the active logger. main.go calls this at startup.
func SetLogger(l *zap.SugaredLogger) {
	slog.Store(l)
}

// L returns the active sugared logger (nop if SetLogger was never called).
func L() *zap.SugaredLogger {
	if p := slog.Load(); p != nil {
		return p
	}
	return zap.NewNop().Sugar()
}

// InitLogger builds a zap logger from cfg. Returns the sugar + a close func.
func InitLogger(cfg LogConfig) (*zap.SugaredLogger, func()) {
	var enc zapcore.Encoder
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.TimeKey = "ts"
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	if cfg.Dev {
		encCfg = zap.NewDevelopmentEncoderConfig()
		encCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
		enc = zapcore.NewConsoleEncoder(encCfg)
	} else {
		enc = zapcore.NewJSONEncoder(encCfg)
	}
	level := zap.InfoLevel
	if cfg.Dev {
		level = zap.DebugLevel
	}

	var sinks []zapcore.WriteSyncer
	sinks = append(sinks, zapcore.AddSync(os.Stderr))
	var lj *lumberjack.Logger
	if cfg.File != "" {
		lj = &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    pickDefault(cfg.MaxSizeMB, 100),
			MaxBackups: pickDefault(cfg.MaxBackups, 7),
			MaxAge:     pickDefault(cfg.MaxAgeDays, 30),
			Compress:   cfg.Compress,
		}
		sinks = append(sinks, zapcore.AddSync(lj))
	}
	core := zapcore.NewCore(enc, zapcore.NewMultiWriteSyncer(sinks...), level)
	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))

	closer := func() {
		_ = logger.Sync()
		if lj != nil {
			_ = lj.Close()
		}
	}
	return logger.Sugar(), closer
}

func pickDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// ---- request_id ----

type ctxKey int

const ctxRequestID ctxKey = 1

// newRequestID returns 32 hex chars from 16 random bytes.
func newRequestID() string {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "0000000000000000"
	}
	return hex.EncodeToString(b[:])
}

// WithRequestID attaches rid to ctx.
func WithRequestID(ctx context.Context, rid string) context.Context {
	return context.WithValue(ctx, ctxRequestID, rid)
}

// RequestID reads rid from ctx; empty if unset.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}
