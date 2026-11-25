package goconsole

import (
	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/goja_nodejs/console"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var _ console.Printer = &GoConsolePrinter{}

// GoConsolePrinter is a console printer for nuclei using gologger
type GoConsolePrinter struct {
	runtime *goja.Runtime
}

func NewGoConsolePrinter() *GoConsolePrinter {
	return &GoConsolePrinter{}
}

func NewRuntimePrinter(runtime *goja.Runtime) *GoConsolePrinter {
	return &GoConsolePrinter{runtime: runtime}
}

func (p *GoConsolePrinter) logger() *gologger.Logger {
	if p.runtime == nil {
		return gologger.DefaultLogger
	}
	return gojs.RuntimeLogger(p.runtime)
}

func (p *GoConsolePrinter) Log(msg string) {
	p.logger().Info().Msg(msg)
}

func (p *GoConsolePrinter) Warn(msg string) {
	p.logger().Warning().Msg(msg)
}

func (p *GoConsolePrinter) Error(msg string) {
	p.logger().Error().Msg(msg)
}
