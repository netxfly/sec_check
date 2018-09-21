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
	"github.com/netxfly/go-autoruns"
	"github.com/olekukonko/tablewriter"

	"sec_check/models"

	"os"
)

func GetAutoruns() (*models.AutoRuns) {
	ret := autoruns.Autoruns()
	return &models.AutoRuns{AutoRuns: ret}
}

func DisplayAutoruns(autoRuns *models.AutoRuns) {
	data := make([][]string, 0)
	for _, autorun := range (autoRuns.AutoRuns) {
		autorunData := make([]string, 0)
		autorunData = append(autorunData, autorun.Type, autorun.ImageName, autorun.Arguments, autorun.MD5)
		data = append(data, autorunData)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Type", "ImageName", "Arguments", "MD5"})
	table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
	table.SetBorder(true)
	table.SetRowLine(true)
	table.SetAutoMergeCells(true)
	table.AppendBulk(data)
	table.SetCaption(true, "Autoruns list")
	table.Render()
}
