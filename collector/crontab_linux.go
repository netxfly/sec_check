// +build linux

package collector

import (
	"io/ioutil"
	"strings"
	"os"

	"github.com/olekukonko/tablewriter"

	"sec_check/models"
)

// GetCrontab 获取计划任务
func GetCronTab() (resultData []models.CronTab) {
	//系统计划任务
	dat, err := ioutil.ReadFile("/etc/crontab")
	if err != nil {
		return resultData
	}
	cronList := strings.Split(string(dat), "\n")
	for _, info := range cronList {
		if strings.HasPrefix(info, "#") || strings.Count(info, " ") < 6 {
			continue
		}
		s := strings.SplitN(info, " ", 7)
		rule := strings.Split(info, " "+s[5])[0]
		m := models.CronTab{Command: s[6], User: s[5], Rule: rule}
		resultData = append(resultData, m)
	}

	//用户计划任务
	dir, err := ioutil.ReadDir("/var/spool/cron/")
	if err != nil {
		return resultData
	}
	for _, f := range dir {
		if f.IsDir() {
			continue
		}
		dat, err = ioutil.ReadFile("/var/spool/cron/" + f.Name())
		if err != nil {
			continue
		}
		cronList = strings.Split(string(dat), "\n")
		for _, info := range cronList {
			if strings.HasPrefix(info, "#") || strings.Count(info, " ") < 5 {
				continue
			}
			s := strings.SplitN(info, " ", 6)
			rule := strings.Split(info, " "+s[5])[0]
			m := models.CronTab{Command: s[5], User: f.Name(), Rule: rule}
			resultData = append(resultData, m)
		}
	}
	return resultData
}

func DisplayCronTab(cronTab []models.CronTab) {
	data := make([][]string, 0)
	for _, item := range cronTab {
		record := make([]string, 0)
		record = append(record, item.Command, item.User, item.Rule)
		data = append(data, record)
	}

	tableCron := tablewriter.NewWriter(os.Stdout)
	tableCron.SetHeader([]string{"command", "user", "rule"})
	tableCron.SetBorder(true)
	tableCron.SetRowLine(true)
	// tableCron.SetAutoMergeCells(true)
	tableCron.AppendBulk(data)
	tableCron.SetCaption(true, "cronTab list")
	tableCron.Render()
}
