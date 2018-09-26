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
	"gopkg.in/abiosoft/ishell.v2"

	"sec_check/collector"
	"sec_check/scanner"
	"sec_check/vars"
	"sec_check/models"
	"sec_check/web/routers"

	"path/filepath"
	"os"
	"strings"
	"encoding/json"
	"net/http"
	"fmt"
	"strconv"
	"sec_check/logger"
)

func Shell(ctx *cli.Context) (err error) {
	shell := ishell.New()
	shell.Println("sec_check Interactive Shell")

	shell.AddCmd(&ishell.Cmd{
		Name: "info",
		Help: "get host info",
		Func: func(c *ishell.Context) {
			c.Println(collector.GetHostInfo())
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "init",
		Help: "init rule from yara files",
		Func: func(c *ishell.Context) {
			scanner.InitRule(vars.RulePath, vars.Debug)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "ps",
		Help: "list process",
		Func: func(c *ishell.Context) {
			ps := collector.GetProcess()
			collector.DisplayProcessList(ps)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "network",
		Help: "list connection",
		Func: func(c *ishell.Context) {
			ps := collector.GetProcess()
			collector.DisplayConnections(ps)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "pstree",
		Help: "list process tree",
		Func: func(c *ishell.Context) {
			ps := collector.GetProcess()
			collector.DisplayProcessTree(ps)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "loginlog",
		Help: "list login record",
		Func: func(c *ishell.Context) {
			loginLogs := collector.GetLoginLog()
			collector.DisplayLoginLog(loginLogs)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "autoruns",
		Help: "list autoruns",
		Func: func(c *ishell.Context) {
			autoruns := collector.GetAutoruns()
			collector.DisplayAutoruns(autoruns)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "crontab",
		Help: "list crontab",
		Func: func(c *ishell.Context) {
			crontab := collector.GetCronTab()
			collector.DisplayCronTab(crontab)
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "scan",
		Help: "Malicious program scanning",
		Func: func(c *ishell.Context) {
			scanType := "process"
			Verbose := false
			scanFiles := ""
			c.ShowPrompt(false)
			defer c.ShowPrompt(true)

			c.Printf("scan type, such as process, file, default is process\nScan Type:\n")
			scanReadLine := c.ReadLine()
			if strings.ToLower(scanReadLine) == "file" {
				scanType = "file"
			}

			c.Printf("verbose, such as true or false, default is false\nVerbose:\n")
			verboseReadLine := c.ReadLine()
			if strings.ToLower(verboseReadLine) == "true" {
				Verbose = true
			}

			vars.Verbose = Verbose

			c.Printf("scan file path, default is \"\"\nFile Path:\n")
			fileReadLine := c.ReadLine()
			if strings.ToLower(fileReadLine) != "" {
				scanFiles = fileReadLine
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
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "dump",
		Help: " dump all result to json",
		Func: func(c *ishell.Context) {
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
		},
	})

	shell.AddCmd(&ishell.Cmd{
		Name: "web",
		Help: "Startup a web server to view check result",
		Func: func(c *ishell.Context) {
			c.ShowPrompt(false)
			defer c.ShowPrompt(true)

			c.Printf("web ip address, default is 127.0.0.1\nAddr:\n")
			addr := c.ReadLine()
			if addr != "" {
				vars.Addr = addr
			}

			c.Printf("web port, default is 8000\nPort:\n")
			port := c.ReadLine()
			if port != "" {
				t, err := strconv.Atoi(port)
				if err == nil {
					vars.Port = t
				}
			}

			logger.Log.Infof("web address: %v:%v", vars.Addr, vars.Port)

			http.HandleFunc("/", routers.Index)
			http.ListenAndServe(fmt.Sprintf("%v:%v", vars.Addr, vars.Port), nil)
		},
	})

	shell.Run()

	return err
}
