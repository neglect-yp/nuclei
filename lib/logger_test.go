package nuclei_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	inputhttp "github.com/projectdiscovery/nuclei/v3/pkg/input/provider/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

type sdkLogOutput struct {
	mu   sync.Mutex
	text strings.Builder
}

func (out *sdkLogOutput) Write(data []byte, _ levels.Level) {
	out.mu.Lock()
	defer out.mu.Unlock()
	out.text.Write(data)
	out.text.WriteByte('\n')
}

func (out *sdkLogOutput) String() string {
	out.mu.Lock()
	defer out.mu.Unlock()
	return out.text.String()
}

func (out *sdkLogOutput) logger() *gologger.Logger {
	logger := &gologger.Logger{}
	logger.SetWriter(out)
	logger.SetFormatter(formatter.NewCLI(true))
	logger.SetMaxLevel(levels.LevelVerbose)
	return logger
}

func TestWithLoggerReceivesProtocolLogs(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	var logs sdkLogOutput
	engine, err := nuclei.NewNucleiEngineCtx(t.Context(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithOptions(types.DefaultOptions()),
		nuclei.WithLogger(logs.logger()),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{writeSDKMatchTemplate(t)}}),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)
	engine.LoadTargets([]string{server.URL}, false)
	require.NoError(t, engine.ExecuteCallbackWithCtx(t.Context()))
	require.Contains(t, logs.String(), "[sdk-callback-match] Sent HTTP request to "+server.URL)
}

func TestWithOptionsAfterWithLoggerKeepsOptionsLogger(t *testing.T) {
	var first, second sdkLogOutput
	opts := types.DefaultOptions()
	logger := second.logger()
	opts.Logger = logger
	engine, err := nuclei.NewNucleiEngineCtx(t.Context(), nuclei.DisableUpdateCheck(), nuclei.WithLogger(first.logger()), nuclei.WithOptions(opts))
	require.NoError(t, err)
	t.Cleanup(engine.Close)
	require.Same(t, logger, engine.Logger)
	require.Same(t, logger, opts.Logger)
}

func TestWithLoggerReceivesOptionWarnings(t *testing.T) {
	var logs sdkLogOutput
	engine, err := nuclei.NewNucleiEngineCtx(t.Context(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{MaxHostError: 1, Timeout: 5}),
		nuclei.WithLogger(logs.logger()),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)
	require.Contains(t, logs.String(), "The concurrency value is higher than max-host-error")
}

func TestThreadSafeWithLogger(t *testing.T) {
	first := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(second.Close)
	var inherited, override sdkLogOutput
	engine, err := nuclei.NewThreadSafeNucleiEngineCtx(t.Context(),
		nuclei.DisableUpdateCheck(),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{writeSDKMatchTemplate(t)}}),
		nuclei.WithLogger(inherited.logger()),
	)
	require.NoError(t, err)
	t.Cleanup(engine.Close)
	complete := make(chan error, 2)
	go func() { complete <- engine.ExecuteNucleiWithOptsCtx(t.Context(), []string{first.URL}) }()
	go func() {
		complete <- engine.ExecuteNucleiWithOptsCtx(t.Context(), []string{second.URL}, nuclei.WithLogger(override.logger()))
	}()
	firstErr, secondErr := <-complete, <-complete
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.Contains(t, inherited.String(), "Sent HTTP request to "+first.URL)
	require.NotContains(t, inherited.String(), second.URL)
	require.Contains(t, override.String(), "Sent HTTP request to "+second.URL)
	require.NotContains(t, override.String(), first.URL)
}

func TestInputFormatKeepsItsLogger(t *testing.T) {
	newInput := func(path string, logs *sdkLogOutput) *inputhttp.HttpInputProvider {
		t.Helper()
		require.NoError(t, os.WriteFile(path, []byte("GET / HTTP/1.1\r\n\r\n"), 0o600))
		input, err := inputhttp.NewHttpInputProviderWithLogger(&inputhttp.HttpMultiFormatOptions{
			InputMode: "http", InputFile: path,
		}, logs.logger())
		require.NoError(t, err)
		return input
	}
	var first, second sdkLogOutput
	pathA := filepath.Join(t.TempDir(), "a.http")
	pathB := filepath.Join(t.TempDir(), "b.http")
	a, b := newInput(pathA, &first), newInput(pathB, &second)
	skip := func(*contextargs.MetaInput) bool { return false }
	a.Iterate(skip)
	b.Iterate(skip)
	require.Contains(t, first.String(), pathA)
	require.NotContains(t, first.String(), pathB)
	require.Contains(t, second.String(), pathB)
	require.NotContains(t, second.String(), pathA)
}
