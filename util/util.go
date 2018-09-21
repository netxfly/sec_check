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

package util

import (
	"github.com/urfave/cli"

	"sec_check/scanner"
	"sec_check/vars"
	"sec_check/collector"
	"sec_check/logger"

	"fmt"
	"sec_check/models"
	"os"
	"encoding/json"
	"path/filepath"
)

func InitRule(ctx *cli.Context) (error) {
	if ctx.IsSet("debug") {
		vars.Debug = ctx.Bool("debug")
	}
	if ctx.IsSet("path") {
		vars.RulePath = ctx.String("path")
	}
	err := scanner.InitRule(vars.RulePath, vars.Debug)
	return err
}

func Ps(ctx *cli.Context) (err error) {
	ps := collector.GetProcess()
	collector.DisplayProcessList(ps)
	return err
}

func Network(ctx *cli.Context) (err error) {
	ps := collector.GetProcess()
	collector.DisplayConnections(ps)
	return err
}

func Tree(ctx *cli.Context) (err error) {
	ps := collector.GetProcess()
	collector.DisplayProcessTree(ps)
	return err
}

func Login(ctx *cli.Context) (err error) {
	loginLogs := collector.GetLoginLog()
	collector.DisplayLoginLog(loginLogs)
	return err
}

func Crontab(ctx *cli.Context) (err error) {
	crontab := collector.GetCronTab()
	collector.DisplayCronTab(crontab)
	return err
}

func Auto(ctx *cli.Context) (err error) {
	autoruns := collector.GetAutoruns()
	collector.DisplayAutoruns(autoruns)
	return err
}

func Info(ctx *cli.Context) (err error) {
	fmt.Println(collector.GetHostInfo())
	return err
}

func Dump(ctx *cli.Context) (err error) {
	info := collector.GetAllInfo()

	{
		scannerEngine, err := scanner.NewScanner(vars.RulesDb)
		if err == nil {
			scannerEngine.ScanProcesses()
			info.ProcessResult = models.DisplayProcessResult()
		}
		scannerEngine.Rules.Destroy()
	}

	outputFile := filepath.Join(vars.CurrentDir, "result.json")
	f, err := os.Create(outputFile)
	if err == nil {
		infoJson, err := json.Marshal(info)
		if err == nil {
			_, err = f.Write(infoJson)
		}
	}

	return err
}

func Scan(ctx *cli.Context) (err error) {
	scanType := "process"
	scanFiles := ""

	if ctx.IsSet("verbose") {
		vars.Verbose = ctx.Bool("verbose")
	}

	if ctx.IsSet("type") {
		scanType = ctx.String("type")
	}

	if ctx.IsSet("file") {
		scanFiles = ctx.String("file")
	}

	if vars.Verbose {
		logger.Log.Debugf("scan_type: %v, scan_file: %v", scanType, scanFiles)
	}

	if scanType == "process" {
		scannerEngine, err := scanner.NewScanner(vars.RulesDb)
		if err == nil {
			scannerEngine.ScanProcesses()
			models.DisplayProcessResult()
		}
		scannerEngine.Rules.Destroy()
	}

	if scanType == "file" {
		scannerEngine, err := scanner.NewScanner(vars.RulesDb)
		if err == nil {
			scannerEngine.ScanFiles(scanFiles)
			models.DisplayFileResult()
		}
		scannerEngine.Rules.Destroy()

	}

	return err
}
