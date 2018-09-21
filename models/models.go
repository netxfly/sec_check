/*

Copyright (c) 2018 sec.lu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THEq
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

package models

import (
	"github.com/hillu/go-yara"

	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/net"
	"github.com/netxfly/gops/goprocess"

	"github.com/netxfly/go-autoruns"

	"sec_check/vars"
	"sec_check/logger"

	"encoding/json"
	"strconv"
	"fmt"
)

type (
	ProcessScanResult struct {
		Pid     int
		Matches []yara.MatchRule
	}

	ProcessResult struct {
		Pid         int
		Path        string
		Namespace   string
		Rule        string
		Description string
	}

	FileScanResult struct {
		FileName string
		Matches  []yara.MatchRule
	}

	FileResult struct {
		Filename    string
		Namespace   string
		Rule        string
		Description string
	}

	CronTab struct {
		Name        string `json:"name,omitempty"`
		Command     string `json:"command,omitempty"`
		Arg         string `json:"arg,omitempty"`
		User        string `json:"user,omitempty"`
		Rule        string `json:"rule,omitempty"`
		Description string `json:"description,omitempty"`
	}

	LoginLog struct {
		Status   bool   `json:"status,omitempty"`
		Username string `json:"username,omitempty"`
		Remote   string `json:"remote,omitempty"`
		Time     string `json:"time,omitempty"`
	}

	Users struct {
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
		Status      string `json:"status,omitempty"`
	}

	HostInfo struct {
		HostInfo      *host.InfoStat
		InterfaceInfo []net.InterfaceStat
	}

	AutoRuns struct {
		AutoRuns []*autoruns.Autorun
	}

	Process struct {
		Process []goprocess.P
	}

	AllInfo struct {
		HostInfo      *HostInfo
		Users         []Users
		AutoRuns      *AutoRuns
		CronTab       []CronTab
		Process       Process
		LoginLog      []LoginLog
		ProcessResult []ProcessResult
		FileResult    []FileResult
	}
)

func SaveProcessResult(err error, result *ProcessScanResult) {
	// logger.Log.Debugf("err: %v, result: %v", err, result)
	if err == nil && len(result.Matches) > 0 {
		pid := fmt.Sprintf("%v", result.Pid)
		vars.ProcessResultMap.Set(pid, result)
	}
}

func DisplayProcessResult() ([]ProcessResult) {
	pResult := make([]ProcessResult, 0)
	for pid, result := range vars.ProcessResultMap.Items() {
		processResult, ok := result.(*ProcessScanResult)
		if ok {
			matches := processResult.Matches
			for _, item := range matches {
				meta := item.Meta
				desc := ""
				v, ok := meta["description"]
				if ok {
					desc = v.(string)
				}
				v1, ok1 := meta["Description"]
				if ok1 {
					desc = v1.(string)
				}
				pidInt, _ := strconv.Atoi(pid)
				p, _ := goprocess.Find(pidInt)
				t := ProcessResult{Pid: pidInt, Path: p.Path, Namespace: item.Namespace, Rule: item.Rule, Description: desc}
				pResult = append(pResult, t)
				logger.Log.Printf("pid: %v, namespace: %v, rule: %v, desc: %v", pid, item.Namespace, item.Rule, desc)
			}
		}
	}
	return pResult
}

func SaveFileResult(err error, result *FileScanResult) {
	if err == nil && len(result.Matches) > 0 {
		vars.FileResultMap.Set(result.FileName, result)
	}
}

func DisplayFileResult() ([]FileResult) {
	fileRet := make([]FileResult, 0)
	for filename, result := range vars.FileResultMap.Items() {
		fileResult, ok := result.(*FileScanResult)
		if ok {
			matches := fileResult.Matches
			for _, item := range matches {
				meta := item.Meta
				desc := ""
				v, ok := meta["description"]
				if ok {
					desc = v.(string)
				}
				v1, ok1 := meta["Description"]
				if ok1 {
					desc = v1.(string)
				}
				t := FileResult{Filename: filename, Namespace: item.Namespace, Rule: item.Rule, Description: desc}
				fileRet = append(fileRet, t)
				logger.Log.Printf("file: %v, namespace: %v, rule: %v, desc: %v", filename, item.Namespace, item.Rule, desc)
			}
		}
	}
	return fileRet
}

func (h *HostInfo) String() string {
	s, _ := json.Marshal(h)
	return string(s)
}
