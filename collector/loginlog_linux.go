// +build linux

package collector

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strings"
	"time"
	"fmt"

	"github.com/olekukonko/tablewriter"

	"sec_check/lib"
	"sec_check/models"
)

type utmp struct {
	UtType uint32
	UtPid  uint32    // PID of login process
	UtLine [32]byte  // device name of tty - "/dev/"
	UtID   [4]byte   // init id or abbrev. ttyname
	UtUser [32]byte  // user name
	UtHost [256]byte // hostname for remote login
	UtExit struct {
		ETermination uint16 // process termination status
		EExit        uint16 // process exit status
	}
	UtSession uint32 // Session ID, used for windowing
	UtTv struct {
		TvSec  uint32 /* Seconds */
		TvUsec uint32 /* Microseconds */
	}
	UtAddrV6 [4]uint32 // IP address of remote host
	Unused   [20]byte  // Reserved for future use
}

func getLast(t string) (result []models.LoginLog) {
	var timestamp int64
	if t == "all" {
		timestamp = 615147123
	} else {
		ti, _ := time.Parse("2006-01-02T15:04:05Z07:00", t)
		timestamp = ti.Unix()
	}
	wtmpFile, err := os.Open("/var/log/wtmp")
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer wtmpFile.Close()
	for {
		wtmp := new(utmp)
		err = binary.Read(wtmpFile, binary.LittleEndian, wtmp)
		if err != nil {
			break
		}
		if wtmp.UtType == 7 && int64(wtmp.UtTv.TvSec) > timestamp {
			m := models.LoginLog{}
			m.Status = true
			m.Remote = string(bytes.TrimRight(wtmp.UtHost[:], "\x00"))
			if m.Remote == "" {
				continue
			}
			m.Username = string(bytes.TrimRight(wtmp.UtUser[:], "\x00"))
			m.Time = time.Unix(int64(wtmp.UtTv.TvSec), 0).Format("2006-01-02T15:04:05Z07:00")
			result = append(result, m)
		}
	}
	return result
}

func getLastb(t string) (result []models.LoginLog) {
	cmd := "lastb -i -F"
	out := lib.Cmdexec(cmd)
	logList := strings.Split(out, "\n")
	for _, v := range logList[0 : len(logList)-3] {
		m := models.LoginLog{}
		s := strings.Fields(v)
		startTime := strings.Join(s[3:8], " ")
		tt, err := time.Parse("Mon Jan 02 15:04:05 2006", startTime)
		if err != nil {
			tt, err = time.Parse("Mon Jan 2 15:04:05 2006", startTime)
			_ = err
		}
		m.Status = false
		m.Username = s[0]
		m.Remote = s[2]
		m.Time = tt.Format("2006-01-02 15:04:05")
		result = append(result, m)
	}
	return result
}

func GetLoginLog() (resultData []models.LoginLog) {
	resultData = getLast("all")
	resultData = append(resultData, getLastb("all")...)
	return resultData
}

func DisplayLoginLog(loginLog []models.LoginLog) {
	data := make([][]string, 0)
	for _, item := range loginLog {
		record := make([]string, 0)
		record = append(record, item.Time, item.Username, item.Remote, fmt.Sprintf("%v", item.Status))
		data = append(data, record)
	}

	tableLogin := tablewriter.NewWriter(os.Stdout)
	tableLogin.SetHeader([]string{"time", "username", "remote", "status"})
	tableLogin.SetBorder(true)
	tableLogin.SetRowLine(true)
	// tableLogin.SetAutoMergeCells(true)
	tableLogin.AppendBulk(data)
	tableLogin.SetCaption(true, "login log record")
	tableLogin.Render()
}
