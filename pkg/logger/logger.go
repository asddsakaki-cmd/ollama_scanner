// pkg/logger/logger.go
// Structured logging with Zap (2026 best practice)

package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	log  *zap.Logger
	once sync.Once
)

// Config holds logger configuration
type Config struct {
	Level      string // debug, info, warn, error
	Format     string // json, console
	File       string // log file path (empty = stdout)
	MaxSize    int    // MB
	MaxBackups int
	MaxAge     int    // days
}

// Init initializes the global logger
func Init(cfg Config) error {
	var err error
	once.Do(func() {
		log, err = createLogger(cfg)
	})
	return err
}

// createLogger creates a new zap logger
func createLogger(cfg Config) (*zap.Logger, error) {
	// Parse log level
	level := zapcore.InfoLevel
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		level = zapcore.InfoLevel
	}
	
	// Configure encoder
	var encoder zapcore.Encoder
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
	
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}
	
	// Configure output
	var writeSyncer zapcore.WriteSyncer
	if cfg.File != "" {
		// File output
		//nolint:gosec // G302: 0644 is standard for log files
		file, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writeSyncer = zapcore.AddSync(file)
	} else {
		// Stdout
		writeSyncer = zapcore.AddSync(os.Stdout)
	}
	
	// Create core
	core := zapcore.NewCore(
		encoder,
		writeSyncer,
		level,
	)
	
	// Create logger
	logger := zap.New(core,
		zap.AddCaller(),
		zap.AddCallerSkip(1),
	)
	
	return logger, nil
}

// L returns the global logger
func L() *zap.Logger {
	if log == nil {
		// Return a no-op logger if not initialized
		return zap.NewNop()
	}
	return log
}

// Debug logs a debug message
func Debug(msg string, fields ...zap.Field) {
	L().Debug(msg, fields...)
}

// Info logs an info message
func Info(msg string, fields ...zap.Field) {
	L().Info(msg, fields...)
}

// Warn logs a warning message
func Warn(msg string, fields ...zap.Field) {
	L().Warn(msg, fields...)
}

// Error logs an error message
func Error(msg string, fields ...zap.Field) {
	L().Error(msg, fields...)
}

// Fatal logs a fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	L().Fatal(msg, fields...)
}

// Sync flushes any buffered log entries
func Sync() error {
	if log != nil {
		return log.Sync()
	}
	return nil
}

// With creates a child logger with additional fields
func With(fields ...zap.Field) *zap.Logger {
	return L().With(fields...)
}

// Named creates a child logger with a new name
func Named(name string) *zap.Logger {
	return L().Named(name)
}

// Field shortcuts
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Bool     = zap.Bool
	Err      = zap.Error  // Use Err instead of Error to avoid conflict
	Float64  = zap.Float64
	Any      = zap.Any
	Time     = zap.Time
	Duration = zap.Duration
)
