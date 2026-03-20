package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"reverse-proxy-mac/src/domain/logger"
)

type ConsoleLogger struct {
	level       logger.Level
	jsonFormat  bool
	output      io.Writer
	fallback    io.Writer
	mu          sync.Mutex
	writeErrors atomic.Uint64
}

func NewConsoleLogger(level logger.Level, jsonFormat bool) *ConsoleLogger {
	return &ConsoleLogger{
		level:      level,
		jsonFormat: jsonFormat,
		output:     os.Stdout,
		fallback:   os.Stderr,
	}
}

func (l *ConsoleLogger) log(level logger.Level, _ context.Context, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.jsonFormat {
		l.logJSON(level, msg, fields)
	} else {
		l.logText(level, msg, fields)
	}
}

func (l *ConsoleLogger) write(data string) {
	if _, err := fmt.Fprintln(l.output, data); err != nil {
		l.writeErrors.Add(1)
		// Fallback to stderr if primary output fails
		if l.fallback != nil && l.fallback != l.output {
			fmt.Fprintln(l.fallback, data) //nolint:errcheck
		}
	}
}

func (l *ConsoleLogger) logJSON(level logger.Level, msg string, fields map[string]interface{}) {
	logEntry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"level":     level.String(),
		"message":   msg,
	}

	for k, v := range fields {
		logEntry[k] = v
	}

	data, err := json.Marshal(logEntry)
	if err != nil {
		l.write(fmt.Sprintf(`{"level":"ERROR","message":"failed to marshal log entry","error":"%v"}`, err))
		return
	}
	l.write(string(data))
}

func (l *ConsoleLogger) logText(level logger.Level, msg string, fields map[string]interface{}) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	var output string

	if len(fields) > 0 {
		fieldsJSON, _ := json.Marshal(fields)
		output = fmt.Sprintf("[%s] %s: %s | %s", timestamp, level.String(), msg, string(fieldsJSON))
	} else {
		output = fmt.Sprintf("[%s] %s: %s", timestamp, level.String(), msg)
	}

	l.write(output)
}

func (l *ConsoleLogger) Debug(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelDebug, ctx, msg, fields)
}

func (l *ConsoleLogger) Info(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelInfo, ctx, msg, fields)
}

func (l *ConsoleLogger) Warn(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelWarn, ctx, msg, fields)
}

func (l *ConsoleLogger) Error(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelError, ctx, msg, fields)
}

// WriteErrors returns the count of write errors encountered.
func (l *ConsoleLogger) WriteErrors() uint64 {
	return l.writeErrors.Load()
}
