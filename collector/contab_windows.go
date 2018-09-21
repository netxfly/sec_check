// +build windows

package collector

import (
	"encoding/xml"
	"log"
	"io/ioutil"
	"runtime"
	"strings"
	"os"

	"github.com/axgle/mahonia"
	"github.com/olekukonko/tablewriter"

	"sec_check/models"
)

type task struct {
	RegistrationInfo struct {
		Description string
	}
	Actions struct {
		Exec struct {
			Command   string
			Arguments string
		}
	}
	Triggers struct {
		CalendarTrigger struct {
			StartBoundary string
		}
	}
	Principals struct {
		Principal struct {
			UserId string
		}
	}
}

// GetCrontab 获取计划任务
func GetCronTab() (resultData []models.CronTab) {
	//系统计划任务
	var taskPath string
	if runtime.GOARCH == "386" {
		taskPath = `C:\Windows\SysNative\Tasks\`
	} else {
		taskPath = `C:\Windows\System32\Tasks\`
	}
	dir, err := ioutil.ReadDir(taskPath)
	if err != nil {
		return resultData
	}
	for _, f := range dir {
		if f.IsDir() {
			continue
		}
		dat, err := ioutil.ReadFile(taskPath + f.Name())
		if err != nil {
			continue
		}
		v := task{}
		dec := mahonia.NewDecoder("utf-16")
		data := dec.ConvertString(string(dat))
		err = xml.Unmarshal([]byte(strings.Replace(data, "UTF-16", "UTF-8", 1)), &v)
		if err != nil {
			log.Println("Windows crontab info xml Unmarshal error: ", err.Error())
			continue
		}
		m := models.CronTab{}
		m.Name = f.Name()
		m.Command = v.Actions.Exec.Command
		m.Arg = v.Actions.Exec.Arguments
		m.User = v.Principals.Principal.UserId
		m.Rule = v.Triggers.CalendarTrigger.StartBoundary
		m.Description = v.RegistrationInfo.Description
		resultData = append(resultData, m)
	}
	return resultData
}

func DisplayCronTab(cronTab []models.CronTab) {
	data := make([][]string, 0)
	for _, item := range cronTab {
		record := make([]string, 0)
		record = append(record, item.Name, item.Command, item.Arg, item.User, item.Rule, item.Description)
		data = append(data, record)
	}

	tableCron := tablewriter.NewWriter(os.Stdout)
	tableCron.SetHeader([]string{"name", "command", "arg", "user", "rule", "description"})
	tableCron.SetBorder(true)
	tableCron.SetRowLine(true)
	// tableCron.SetAutoMergeCells(true)
	tableCron.AppendBulk(data)
	tableCron.SetCaption(true, "crontab list")
	tableCron.Render()
}
