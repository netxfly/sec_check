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

import "sec_check/models"

func GetAllInfo() (info *models.AllInfo) {
	hostInfo, _ := GetHostInfo()
	ps := GetProcess()
	autoRuns := GetAutoruns()
	cronTab := GetCronTab()
	loginLogs := GetLoginLog()
	users := GetUser()
	processResult := make([]models.ProcessResult, 0)
	fileResult := make([]models.FileResult, 0)

	return &models.AllInfo{HostInfo: hostInfo, Users: users, AutoRuns: autoRuns, CronTab: cronTab, LoginLog: loginLogs,
		Process: ps, ProcessResult: processResult, FileResult: fileResult}
}
