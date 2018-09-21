// +build windows

package collector

import (
	"github.com/StackExchange/wmi"

	"sec_check/models"
)

type userAccount struct {
	Name        string // 用户名
	Description string // 用户描述
	Status      string // 用户状态
}

// GetUser 获取系统用户列表
func GetUser() (resultData []models.Users) {
	var dst []userAccount
	err := wmi.Query("SELECT * FROM Win32_UserAccount where LocalAccount=TRUE", &dst)
	if err != nil {
		return resultData
	}
	for _, v := range dst {
		m := models.Users{}
		m.Name = v.Name
		m.Description = v.Description
		m.Status = v.Status
		resultData = append(resultData, m)
	}
	return resultData
}
