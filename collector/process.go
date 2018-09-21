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

package collector

import (
	"fmt"
	"strconv"
	"strings"
	"os"

	"github.com/netxfly/gops/goprocess"
	"github.com/xlab/treeprint"
	"github.com/olekukonko/tablewriter"

	"sec_check/models"
)

func DisplayProcessList(ps models.Process) {
	data := make([][]string, 0)
	for _, p := range ps.Process {
		processList := make([]string, 0)
		processList = append(processList, fmt.Sprintf("%v", p.PPID), fmt.Sprintf("%v", p.PID),
			p.Path, p.Arguments, p.Username, p.Uid)
		data = append(data, processList)
	}

	// 打印进程信息表
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"ppid", "pid", "path", "Arguments", "username", "uid"})
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)
	table.AppendBulk(data)
	table.SetCaption(true, "Process list")
	table.Render()

}

func DisplayConnections(ps models.Process) {
	networkData := make([][]string, 0)
	for _, p := range ps.Process {
		connList := make([]string, 0)
		connection := make([]string, 0)
		for _, conn := range p.ConnectionStates {
			if conn.Family == 1 {
				continue
			}
			c := fmt.Sprintf("%v:%v<->%v:%v(%v)\n",
				conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port, conn.Status)
			connection = append(connection, c)
		}
		if len(connection) > 0 {
			network := strings.Join(connection, "")
			connList = append(connList, fmt.Sprintf("%v", p.PID), fmt.Sprintf("%v", p.Username),
				p.Arguments, network)
			networkData = append(networkData, connList)
		}
	}

	// 打印网络连接信息表
	tableConn := tablewriter.NewWriter(os.Stdout)
	tableConn.SetHeader([]string{"pid", "user", "path", "local/remote(TCP Status)"})
	tableConn.SetBorder(true)
	tableConn.SetRowLine(true)
	tableConn.SetAutoMergeCells(true)
	tableConn.AppendBulk(networkData)
	tableConn.SetCaption(true, "Connections list")
	tableConn.Render()
}

func GetProcess() (models.Process) {
	ps := goprocess.FindAll()
	return models.Process{Process: ps}
}

// pstree contains a mapping between the PPIDs and the child processes.
var pstree map[int][]goprocess.P

// displayProcessTree displays a tree of all the running Go processes.
func DisplayProcessTree(ps models.Process) {
	pstree = make(map[int][]goprocess.P)
	for _, p := range ps.Process {
		pstree[p.PPID] = append(pstree[p.PPID], p)
	}
	tree := treeprint.New()
	tree.SetValue("...")
	seen := map[int]bool{}
	for _, p := range ps.Process {
		constructProcessTree(p.PPID, p, seen, tree)
	}
	fmt.Println(tree.String())
}

// constructProcessTree constructs the process tree in a depth-first fashion.
func constructProcessTree(ppid int, p goprocess.P, seen map[int]bool, tree treeprint.Tree) {
	if seen[ppid] {
		return
	}
	seen[ppid] = true
	if ppid != p.PPID {
		output := strconv.Itoa(ppid) + " (" + p.Path + " " + p.Arguments + " " + fmt.Sprintf("user:%v, uid:%v",
			p.Username, p.Uid) + ")"
		tree = tree.AddBranch(output)
	} else {
		output := strconv.Itoa(ppid) + " (" + p.Path + " " + p.Arguments + " " + fmt.Sprintf("user:%v, uid:%v",
			p.Username, p.Uid) + ")"
		tree = tree.AddBranch(output)
	}
	for index := range pstree[ppid] {
		p := pstree[ppid][index]
		constructProcessTree(p.PID, p, seen, tree)
	}
}
