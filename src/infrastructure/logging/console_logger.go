package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"reverse-proxy-mac/src/domain/logger"
)

type ConsoleLogger struct {
	level      logger.Level
	jsonFormat bool
}

func NewConsoleLogger(level logger.Level, jsonFormat bool) *ConsoleLogger {
	return &ConsoleLogger{
		level:      level,
		jsonFormat: jsonFormat,
	}
}

func (l *ConsoleLogger) log(level logger.Level, levelStr string, ctx context.Context, msg string, fields map[string]interface{}) {
	if level < l.level {
		return
	}

	if l.jsonFormat {
		l.logJSON(levelStr, msg, fields)
	} else {
		l.logText(levelStr, msg, fields)
	}
}

func (l *ConsoleLogger) logJSON(level, msg string, fields map[string]interface{}) {
	logEntry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level,
		"message":   msg,
	}

	if fields != nil {
		logEntry["fields"] = fields
	}

	data, _ := json.Marshal(logEntry)
	log.Println(string(data))
}

func (l *ConsoleLogger) logText(level, msg string, fields map[string]interface{}) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	output := fmt.Sprintf("[%s] %s: %s", timestamp, level, msg)

	if len(fields) > 0 {
		fieldsJSON, _ := json.Marshal(fields)
		output += fmt.Sprintf(" | %s", string(fieldsJSON))
	}

	log.Println(output)
}

func (l *ConsoleLogger) Debug(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelDebug, "DEBUG", ctx, msg, fields)
}

func (l *ConsoleLogger) Info(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelInfo, "INFO", ctx, msg, fields)
}

func (l *ConsoleLogger) Warn(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelWarn, "WARN", ctx, msg, fields)
}

func (l *ConsoleLogger) Error(ctx context.Context, msg string, fields map[string]interface{}) {
	l.log(logger.LevelError, "ERROR", ctx, msg, fields)
}
