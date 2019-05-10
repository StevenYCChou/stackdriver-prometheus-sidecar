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

package disk

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/golang/protobuf/proto"
	monitoring "google.golang.org/genproto/googleapis/monitoring/v3"
)

type DiskClient struct {
	logger log.Logger
	file *os.File
}

// NewDiskClient creates a new DiskClient.
func NewDiskClient(logger log.Logger) *DiskClient {
        if logger == nil {
                logger = log.NewNopLogger()
        }
	tmpOutputDir := os.TempDir() + "/stackdriver-prometheus-sidecar/CreateTimeSeriesRequest"
	err := os.MkdirAll(tmpOutputDir, 0700)
	if err != nil {
		level.Warn(logger).Log(
			"msg", "failure creating directory.",
			"err", err)
	}
	file, err := ioutil.TempFile(tmpOutputDir, "*.txt")
	if err != nil {
		level.Warn(logger).Log(
			"msg", "failure creating files.",
			"err", err)
	}
	return &DiskClient{
		file: file,
		logger: logger,
	}
}

// Store put a batch of samples to the disk.
func (dc *DiskClient) Store(req *monitoring.CreateTimeSeriesRequest) error {
	data, err := proto.Marshal(req)
	if err != nil {
		fmt.Println(err)
		return err
	}
	_, err = dc.file.Write(data)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func (dc *DiskClient) Close() error {
	return dc.file.Close()
}
