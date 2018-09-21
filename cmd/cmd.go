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

package cmd

import (
	"github.com/urfave/cli"
	"sec_check/util"
	"sec_check/web"
)

var Init = cli.Command{
	Name:        "init",
	Usage:       "init rule from yara files",
	Description: "init rule from yara files",
	Action:      util.InitRule,
	Flags: []cli.Flag{
		boolFlag("debug, d", "debug mode"),
		stringFlag("path, p", "rules", "yara rules path"),
	},
}

var Ps = cli.Command{
	Name:        "ps",
	Usage:       "list process",
	Description: "list process",
	Action:      util.Ps,
}

var Connections = cli.Command{
	Name:        "netstat",
	Usage:       "list connection",
	Description: "list connection",
	Action:      util.Network,
}

var Tree = cli.Command{
	Name:        "pstree",
	Usage:       "list process tree",
	Description: "list process tree",
	Action:      util.Tree,
}

var Login = cli.Command{
	Name:        "loginlog",
	Usage:       "list login record",
	Description: "list login record",
	Action:      util.Login,
}

var Crontab = cli.Command{
	Name:        "crontab",
	Usage:       "list crontab",
	Description: "list crontab",
	Action:      util.Crontab,
}

var Auto = cli.Command{
	Name:        "autoruns",
	Usage:       "list autoruns",
	Description: "list autoruns",
	Action:      util.Auto,
}

var Info = cli.Command{
	Name:        "info",
	Usage:       "host info",
	Description: "host info",
	Action:      util.Info,
}

var Scan = cli.Command{
	Name:        "scan",
	Usage:       "Malicious program scanning",
	Description: "Malicious program scanning",
	Action:      util.Scan,
	Flags: []cli.Flag{
		stringFlag("type, t", "process", "scan type, such as: process, file"),
		stringFlag("file, f", "", "File path to scan"),
		boolFlag("verbose, vv", "verbose mode"),
	},
}

var Dump = cli.Command{
	Name:        "dump",
	Usage:       "dump all result to json",
	Description: "dump all result to json",
	Action:      util.Dump,
}

var Web = cli.Command{
	Name:        "web",
	Usage:       "Startup a web server to view check result",
	Description: "Startup a web server to view check result",
	Action:      web.RunWeb,
	Flags: []cli.Flag{
		stringFlag("server", "", "http server address"),
		intFlag("port", 8000, "http port"),
	},
}

var Shell = cli.Command{
	Name:        "shell",
	Usage:       "Interactive shell",
	Description: "Interactive shell",
	Action:      "",
}

func stringFlag(name, value, usage string) cli.StringFlag {
	return cli.StringFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}

func boolFlag(name, usage string) cli.BoolFlag {
	return cli.BoolFlag{
		Name:  name,
		Usage: usage,
	}
}

func intFlag(name string, value int, usage string) cli.IntFlag {
	return cli.IntFlag{
		Name:  name,
		Value: value,
		Usage: usage,
	}
}
