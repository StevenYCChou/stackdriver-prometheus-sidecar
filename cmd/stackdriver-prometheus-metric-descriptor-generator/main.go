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
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof" // Comment this line to disable pprof endpoint.
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"runtime"

	"github.com/Stackdriver/stackdriver-prometheus-sidecar/metadata"
	"github.com/Stackdriver/stackdriver-prometheus-sidecar/targets"
	"github.com/ghodss/yaml"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/api"
	"github.com/prometheus/common/promlog"
	promlogflag "github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/pkg/textparse"
	"github.com/prometheus/prometheus/scrape"
	"go.opencensus.io/plugin/ochttp"
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

type apiResponse struct {
	Status    string          `json:"status"`
	Data      apiResponseData `json:"data"`
	Error     string          `json:"error"`
	ErrorType string          `json:"errorType"`
}

type apiResponseData struct {
	Result []apiResponseDataResult `json:"result"`
}

type apiResponseDataResult struct {
	Metric labels.Labels `json:"metric"`
}

const (
	metricSuffixBucket = "_bucket"
	metricSuffixSum    = "_sum"
	metricSuffixCount  = "_count"
)

func main() {
	if os.Getenv("DEBUG") != "" {
		runtime.SetBlockProfileRate(20)
		runtime.SetMutexProfileFraction(20)
	}

	cfg := struct {
		configFilename string
		metricsPrefix  string
		prometheusURL  *url.URL
		filters        []string
		filtersets     []string
		metricRenames  map[string]string
		staticMetadata []scrape.MetricMetadata

		logLevel promlog.AllowedLevel
	}{}

	a := kingpin.New(filepath.Base(os.Args[0]), "The Prometheus monitoring server")

	a.Version(version.Print("prometheus"))

	a.HelpFlag.Short('h')

	a.Flag("config-file", "A configuration file.").StringVar(&cfg.configFilename)

	a.Flag("prometheus.api-address", "Address to listen on for UI, API, and telemetry.").
		Default("http://127.0.0.1:9090/").URLVar(&cfg.prometheusURL)

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

	promCfg := api.Config{
		Address: (*cfg.prometheusURL).String(),
	}

	promClient, err := api.NewClient(promCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, errors.Wrapf(err, "Error creating Prometheus confg."))
	}

	url := promClient.URL("api/v1/query", nil)
	q := url.Query()
	q.Set("query", "{__name__=~\".+\"}")
	url.RawQuery = q.Encode()
	fmt.Println(url.String())

	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		level.Error(logger).Log("err", err)
	}
	fmt.Println(req.URL)
	_, body, err := promClient.Do(context.Background(), req)
	if err != nil {
		level.Error(logger).Log("err", err)
	}

	var res apiResponse
	err = json.Unmarshal(body, &res)

	// create target cache
	targetsURL, err := cfg.prometheusURL.Parse(targets.DefaultAPIEndpoint)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	httpClient := &http.Client{Transport: &ochttp.Transport{}}
	targetCache := targets.NewCache(logger, httpClient, targetsURL)

	// create metadata cache
	metadataURL, err := cfg.prometheusURL.Parse(metadata.DefaultEndpointPath)
	if err != nil {
		panic(err)
	}
	metadataCache := metadata.NewCache(httpClient, metadataURL, cfg.staticMetadata)

	// pass 1: consume all the results. drop target labels from all the labels. also drop __name__ label
	// also build up metadata cache
	metricNameToLabels := map[string]map[string]bool{}
	for _, result := range res.Data.Result {
		target, err := targetCache.Get(ctx, result.Metric)
		if err != nil {
			level.Info(logger).Log("retrieving target failed")
		}

		metricLabels := targets.DropTargetLabels(result.Metric, target.Labels)
		// fmt.Println(metricLabels)

		metricName := result.Metric.Get("__name__")

		jobName := result.Metric.Get("job")
		instanceName := result.Metric.Get("instance")
		metadataCache.Get(ctx, jobName, instanceName, metricName)
		// fmt.Println(metricName)
		if _, ok := metricNameToLabels[metricName]; !ok {
			metricNameToLabels[metricName] = map[string]bool{}
		}
		for _, label := range metricLabels {
			if label.Name == "__name__" {
				continue
			}
			metricNameToLabels[metricName][label.Name] = true
		}
	}

	// pass 2: check whether histogram exists. if exists, construct a metric without postfix, remove le from labels, and group all the labels.
	metricNameToLabelsWithoutHistogram := map[string]map[string]bool{}
	for k, labels := range(metricNameToLabels) {
		var metricPrefix string
		if strings.HasSuffix(k, metricSuffixBucket) {
			metricPrefix = k[:len(k)-len(metricSuffixBucket)]
		}
		if strings.HasSuffix(k, metricSuffixCount) {
			metricPrefix = k[:len(k)-len(metricSuffixCount)]
		}
		if strings.HasSuffix(k, metricSuffixSum) {
			metricPrefix = k[:len(k)-len(metricSuffixSum)]
		}

		if len(metricPrefix) != 0 {
			allDistributionMetricNames := []string{
				fmt.Sprintf("%s%s", metricPrefix, metricSuffixBucket),
				fmt.Sprintf("%s%s", metricPrefix, metricSuffixCount),
				fmt.Sprintf("%s%s", metricPrefix, metricSuffixSum),
			}
			hasDistribution := true
			for _, s := range allDistributionMetricNames {
				if _, ok := metricNameToLabels[s]; !ok {
					hasDistribution = false
				} 
			}

			if hasDistribution {
				fmt.Println("distribution metric name:", metricPrefix)
				if _, ok := metricNameToLabelsWithoutHistogram[metricPrefix]; !ok {
					metricNameToLabelsWithoutHistogram[metricPrefix] = map[string]bool{}
				}
				for l, _ := range(labels) {
					if l != "le" {
						fmt.Println("distribution labels:", l)
						metricNameToLabelsWithoutHistogram[metricPrefix][l] = true
					}
				}
				continue
			}
		}

		if _, ok := metricNameToLabelsWithoutHistogram[k]; !ok {
			metricNameToLabelsWithoutHistogram[k] = map[string]bool{}
		}
		for l, _ := range(labels) {
			metricNameToLabelsWithoutHistogram[k][l] = true
		}

	}

	// pass 3: reconstruct as metric_name -> slice of label keys 
	metricNameToLabelNames := map[string][]string{}
	for k, v := range(metricNameToLabelsWithoutHistogram) {
		labels := []string{}
		for k2, _ := range(v) {
			labels = append(labels, k2)
		}
		metricNameToLabelNames[k] = labels
		fmt.Println("metric name: ", k)
		fmt.Println("labels: ", labels)
	}
	// TODO:
	// 1-1) find out histogram type.
	//  rule:
	//    if it has _bucket or _sum or _count as suffix, go into checking function
	//         if all 3 check exists return true and the metric name
	//         if true, return metric name and query all metrics and stuff the labels
	//    if yes, then create a new metric with the metric name without suffix, and remove le label
	// 1-2) construct the metric name & use 'distribution' type
	// 1-3) remove le from labels 
    

	level.Info(logger).Log("msg", "See you next time!")
}

func stripComplexMetricSuffix(name string) (string, string, bool) {
	if strings.HasSuffix(name, metricSuffixBucket) {
		return name[:len(name)-len(metricSuffixBucket)], metricSuffixBucket, true
	}
	if strings.HasSuffix(name, metricSuffixCount) {
		return name[:len(name)-len(metricSuffixCount)], metricSuffixCount, true
	}
	if strings.HasSuffix(name, metricSuffixSum) {
		return name[:len(name)-len(metricSuffixSum)], metricSuffixSum, true
	}
	return name, "", false
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
