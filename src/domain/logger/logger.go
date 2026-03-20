// Package logger defines the logging interface and log levels for the application.
package logger

import "context"

// Level represents the severity level of a log message.
type Level int

const (
	// LevelDebug is for detailed debugging information.
	LevelDebug Level = iota
	// LevelInfo is for general operational information.
	LevelInfo
	// LevelWarn is for warning messages that indicate potential issues.
	LevelWarn
	// LevelError is for error messages that indicate failures.
	LevelError
)

// String returns the string representation of the log level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger defines the interface for logging operations.
// All methods accept a context for potential correlation ID extraction
// and a fields map for structured logging.
type Logger interface {
	Debug(ctx context.Context, msg string, fields map[string]interface{})
	Info(ctx context.Context, msg string, fields map[string]interface{})
	Warn(ctx context.Context, msg string, fields map[string]interface{})
	Error(ctx context.Context, msg string, fields map[string]interface{})
}
