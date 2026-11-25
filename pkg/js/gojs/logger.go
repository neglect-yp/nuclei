package gojs

import (
	"context"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/logging"
)

func RuntimeLogger(runtime *goja.Runtime) *gologger.Logger {
	value, _ := runtime.GetContextValue("ctx")
	ctx, _ := value.(context.Context)
	return logging.FromContext(ctx)
}
