// +build linux

package collector

import (
	"io/ioutil"
	"strings"

	"sec_check/models"
)

// GetUser 获取系统用户列表
func GetUser() (resultData []models.Users) {
	dat, err := ioutil.ReadFile("/etc/passwd")
	if err != nil {
		return resultData
	}
	userList := strings.Split(string(dat), "\n")
	if len(userList) < 2 {
		return
	}
	for _, info := range userList[0 : len(userList)-2] {
		if strings.Contains(info, "/nologin") {
			continue
		}
		s := strings.SplitN(info, ":", 2)
		m := models.Users{Name: s[0], Description: s[1]}
		resultData = append(resultData, m)
	}
	return resultData
}
