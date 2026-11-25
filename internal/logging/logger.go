package logging

import (
	"context"

	"github.com/projectdiscovery/gologger"
)

type contextKey struct{}

func WithLogger(ctx context.Context, logger *gologger.Logger) context.Context {
	return context.WithValue(ctx, contextKey{}, logger)
}

func FromContext(ctx context.Context) *gologger.Logger {
	return FromContextOr(ctx, nil)
}

// FromContextOr uses the owning component's logger outside a scan context.
func FromContextOr(ctx context.Context, fallback *gologger.Logger) *gologger.Logger {
	if ctx != nil {
		if logger, ok := ctx.Value(contextKey{}).(*gologger.Logger); ok && logger != nil {
			return logger
		}
	}
	return OrDefault(fallback)
}

func OrDefault(logger *gologger.Logger) *gologger.Logger {
	if logger == nil {
		return gologger.DefaultLogger
	}
	return logger
}

// Print keeps request dumps at info level and preserves the CLI's unlabeled
// output. Logger.Print uses the silent level and writes to stdout.
func Print(logger *gologger.Logger) *gologger.Event {
	if logger == gologger.DefaultLogger {
		return gologger.Print()
	}
	return logger.Info()
}
