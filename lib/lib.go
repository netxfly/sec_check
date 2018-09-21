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

package lib

import (
	"os/exec"
	"runtime"
	"strings"
	"log"

	"github.com/axgle/mahonia"
	"regexp"
	"path/filepath"
)

// Cmdexec 执行系统命令
func Cmdexec(cmd string) string {
	var c *exec.Cmd
	var data string
	system := runtime.GOOS
	argArray := strings.Split(cmd, " ")
	c = exec.Command(argArray[0], argArray[1:]...)
	out, _ := c.CombinedOutput()
	data = string(out)
	if system == "windows" {
		dec := mahonia.NewDecoder("gbk")
		data = dec.ConvertString(data)
	}
	return data
}

// InArray 判断是否存在列表中，如果regex为true，则进行正则匹配
func InArray(list []string, value string, regex bool) bool {
	for _, v := range list {
		if regex {
			if ok, err := regexp.Match(v, []byte(value)); ok {
				return true
			} else if err != nil {
				log.Println(err.Error())
			}
		} else {
			if value == v {
				return true
			}
		}
	}
	return false
}

func GetCurDir() (string) {
	dir, err := filepath.Abs(filepath.Dir("./"))
	if err != nil {
		log.Fatal(err)
	}
	return dir
}
