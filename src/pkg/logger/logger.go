package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"reverse-proxy-mac/src/internal/domain/ports"
)

type Level int

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
)

type standardLogger struct {
	level  Level
	logger *log.Logger
}

// NewLogger creates a new logger instance
func NewLogger(levelStr string) ports.Logger {
	level := parseLevel(levelStr)
	return &standardLogger{
		level:  level,
		logger: log.New(os.Stdout, "", 0),
	}
}

func parseLevel(levelStr string) Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	default:
		return InfoLevel
	}
}

func (l *standardLogger) log(level Level, levelStr, msg string, keysAndValues ...interface{}) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format(time.RFC3339)
	logMsg := fmt.Sprintf("[%s] %s: %s", timestamp, levelStr, msg)

	if len(keysAndValues) > 0 {
		logMsg += " |"
		for i := 0; i < len(keysAndValues); i += 2 {
			if i+1 < len(keysAndValues) {
				logMsg += fmt.Sprintf(" %v=%v", keysAndValues[i], keysAndValues[i+1])
			}
		}
	}

	l.logger.Println(logMsg)
}

func (l *standardLogger) Debug(msg string, keysAndValues ...interface{}) {
	l.log(DebugLevel, "DEBUG", msg, keysAndValues...)
}

func (l *standardLogger) Info(msg string, keysAndValues ...interface{}) {
	l.log(InfoLevel, "INFO", msg, keysAndValues...)
}

func (l *standardLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.log(WarnLevel, "WARN", msg, keysAndValues...)
}

func (l *standardLogger) Error(msg string, keysAndValues ...interface{}) {
	l.log(ErrorLevel, "ERROR", msg, keysAndValues...)
}

func (l *standardLogger) Fatal(msg string, keysAndValues ...interface{}) {
	l.log(FatalLevel, "FATAL", msg, keysAndValues...)
	os.Exit(1)
}
