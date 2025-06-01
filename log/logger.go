package log

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

var (
	defaultLogger = New()
)

type Logger struct {
	*slog.Logger
}

func New() *Logger {
	sl := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return &Logger{sl}
}

func Default() *Logger {
	return defaultLogger
}

func (l *Logger) Info(msg string, msgs ...any) {
	strs := make([]string, 0, len(msgs)+1)
	strs = append(strs, msg)
	for _, m := range msgs {
		strs = append(strs, fmt.Sprintf("%v", m))
	}
	l.Infof(strings.Join(strs, " "))
}

func (l *Logger) Infof(format string, args ...any) {
	l.Logger.Info(fmt.Sprintf(format+"\n", args...))
}

func (l *Logger) Errorf(format string, args ...any) {
	l.Logger.Error(fmt.Sprintf(format+"\n", args...))
}

func (l *Logger) Warnf(format string, args ...any) {
	l.Logger.Warn(fmt.Sprintf(format+"\n", args...))
}
