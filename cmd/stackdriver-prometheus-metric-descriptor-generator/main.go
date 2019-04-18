/*
Copyright 2019 Google Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"fmt"
	"io/ioutil"
	_ "net/http/pprof" // Comment this line to disable pprof endpoint.
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Stackdriver/stackdriver-prometheus-sidecar/metadata"
	"github.com/ghodss/yaml"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/common/promlog"
	promlogflag "github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/prometheus/pkg/textparse"
	"github.com/prometheus/prometheus/scrape"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

type fileConfig struct {
	MetricRenames []struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"metric_renames"`

	StaticMetadata []struct {
		Metric string `json:"metric"`
		Type   string `json:"type"`
		Help   string `json:"help"`
	} `json:"static_metadata"`
}

func main() {
	if os.Getenv("DEBUG") != "" {
		runtime.SetBlockProfileRate(20)
		runtime.SetMutexProfileFraction(20)
	}

	cfg := struct {
		configFilename     string
		metricsPrefix      string
		prometheusURL      *url.URL
		listenAddress      string
		filters            []string
		filtersets         []string
		metricRenames      map[string]string
		staticMetadata     []scrape.MetricMetadata

		logLevel promlog.AllowedLevel
	}{}

	a := kingpin.New(filepath.Base(os.Args[0]), "The Prometheus monitoring server")

	a.Version(version.Print("prometheus"))

	a.HelpFlag.Short('h')

	a.Flag("config-file", "A configuration file.").StringVar(&cfg.configFilename)

	a.Flag("prometheus.api-address", "Address to listen on for UI, API, and telemetry.").
		Default("http://127.0.0.1:9090/").URLVar(&cfg.prometheusURL)

	a.Flag("web.listen-address", "Address to listen on for UI, API, and telemetry.").
		Default("0.0.0.0:9091").StringVar(&cfg.listenAddress)

	a.Flag("include", "PromQL metric and label matcher which must pass for a series to be forwarded to Stackdriver. If repeated, the series must pass any of the filter sets to be forwarded.").
		StringsVar(&cfg.filtersets)

	a.Flag("filter", "PromQL-style matcher for a single label which must pass for a series to be forwarded to Stackdriver. If repeated, the series must pass all filters to be forwarded. Deprecated, please use --include instead.").
		StringsVar(&cfg.filters)

	promlogflag.AddFlags(a, &cfg.logLevel)

	_, err := a.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, errors.Wrapf(err, "Error parsing commandline arguments"))
		a.Usage(os.Args[1:])
		os.Exit(2)
	}

	logger := promlog.New(cfg.logLevel)
	if cfg.configFilename != "" {
		cfg.metricRenames, cfg.staticMetadata, err = parseConfigFile(cfg.configFilename)
		if err != nil {
			msg := fmt.Sprintf("Parse config file %s", cfg.configFilename)
			level.Error(logger).Log("msg", msg, "err", err)
			os.Exit(2)
		}
	}

	// if err := g.Run(); err != nil {
	// 	level.Error(logger).Log("err", err)
	// }
	level.Info(logger).Log("msg", "See you next time!")
}

func parseConfigFile(filename string) (map[string]string, []scrape.MetricMetadata, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, errors.Wrap(err, "reading file")
	}
	var fc fileConfig
	if err := yaml.Unmarshal(b, &fc); err != nil {
		return nil, nil, errors.Wrap(err, "invalid YAML")
	}
	renameMapping := map[string]string{}
	for _, r := range fc.MetricRenames {
		renameMapping[r.From] = r.To
	}
	var staticMetadata []scrape.MetricMetadata
	for _, sm := range fc.StaticMetadata {
		switch sm.Type {
		case metadata.MetricTypeUntyped:
			// Convert "untyped" to the "unknown" type used internally as of Prometheus 2.5.
			sm.Type = textparse.MetricTypeUnknown
		case textparse.MetricTypeCounter, textparse.MetricTypeGauge, textparse.MetricTypeHistogram,
			textparse.MetricTypeSummary, textparse.MetricTypeUnknown:
		default:
			return nil, nil, errors.Errorf("invalid metric type %q", sm.Type)
		}
		staticMetadata = append(staticMetadata, scrape.MetricMetadata{
			Metric: sm.Metric,
			Type:   textparse.MetricType(sm.Type),
			Help:   sm.Help,
		})
	}
	return renameMapping, staticMetadata, nil
}
