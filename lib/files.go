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
	"os"
	"path/filepath"
)

func GetFiles(filePath string) (Files []string, err error) {
	// Check if the path exists.
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return Files, err
	}
	rulesStat, _ := os.Stat(filePath)
	switch mode := rulesStat.Mode(); {
	// Check if the path is a folder...
	case mode.IsDir():
		err = filepath.Walk(filePath, func(filePath string, fileObj os.FileInfo, err error) error {
			rulesObj, err := os.Open(filePath)
			defer rulesObj.Close()
			if err == nil {
				Files = append(Files, filePath)
			}
			return nil
		})
	case mode.IsRegular():
		rulesObj, err := os.Open(filePath)
		defer rulesObj.Close()
		if err == nil {
			Files = append(Files, filePath)
		}
	}
	return Files, err
}
