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

package main

import (
	"os"
	"runtime"

	"github.com/urfave/cli"

	"sec_check/cmd"
	"sec_check/vars"
	"sec_check/lib"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	vars.CurrentDir = lib.GetCurDir()
}

func main() {
	app := cli.NewApp()
	app.Name = "xsec checker"
	app.Author = "netxfly"
	app.Email = "x@xsec.io"
	app.Version = "20180921"
	app.Usage = "Cross platform security detection tool"
	app.Commands = []cli.Command{cmd.Info, cmd.Init, cmd.Ps, cmd.Connections, cmd.Tree, cmd.Login, cmd.Auto,
		cmd.Crontab, cmd.Scan, cmd.Dump, cmd.Web}
	app.Flags = append(app.Flags, cmd.Init.Flags...)
	app.Flags = append(app.Flags, cmd.Scan.Flags...)
	app.Flags = append(app.Flags, cmd.Web.Flags...)

	app.Run(os.Args)
}
