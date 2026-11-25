package dsl_test

import (
	"bytes"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/govaluate"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestPrintDebugUsesExecutionLogger(t *testing.T) {
	for _, name := range []string{"print_debug", "printdebug"} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := &gologger.Logger{}
			logger.SetWriter(&utils.CaptureWriter{Buffer: &logs})
			logger.SetFormatter(formatter.NewCLI(true))
			logger.SetMaxLevel(levels.LevelDebug)
			expression, err := govaluate.NewEvaluableExpressionWithFunctions(name+"('hello')", dsl.HelperFunctions)
			require.NoError(t, err)
			result, err := dsl.EvalWithOptions(expression, nil, &types.Options{Logger: logger})
			require.NoError(t, err)
			require.Equal(t, true, result)
			require.Contains(t, logs.String(), "print_debug value: hello")
		})
	}
}
