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

package scanner

import (
	"os"
	"path"
	"path/filepath"

	"github.com/hillu/go-yara"

	"sec_check/logger"
	"strings"
)

func TestRule(rulesPath string, debug bool) (ruleFiles []string) {
	// Check if the path exists.
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		panic(err)
	}
	rulesStat, _ := os.Stat(rulesPath)
	switch mode := rulesStat.Mode(); {
	// Check if the path is a folder...
	case mode.IsDir():
		filepath.Walk(rulesPath, func(filePath string, fileObj os.FileInfo, err error) error {
			// Get the file name.
			fileName := fileObj.Name()
			// Check if the file has extension .yar or .yara.
			if (path.Ext(fileName) == ".yar") || (path.Ext(fileName) == ".yara") {
				// Open the rule file and add it to the Yara compiler.
				rulesObj, err := os.Open(filePath)
				defer rulesObj.Close()
				if err == nil {
					compiler, err := yara.NewCompiler()
					if err != nil {
						logger.Log.Panic(err)
					}
					errRet := compiler.AddFile(rulesObj, "")
					if errRet == nil {
						ruleFiles = append(ruleFiles, filePath)
					} else {
						if debug {
							logger.Log.Debugf("invalid rule file: %v, detail: %v", filePath, errRet)
						}
						// os.Remove(filePath)
					}
				}
			}
			return nil
		})
		// Check if it is a file instead...
	case mode.IsRegular():
		// Open the rule file and add it to the Yara compiler.
		rulesObj, err := os.Open(rulesPath)
		defer rulesObj.Close()
		if err == nil {
			compiler, err := yara.NewCompiler()
			if err != nil {
				logger.Log.Panic(err)
			}
			errRet := compiler.AddFile(rulesObj, "")
			if errRet == nil {
				ruleFiles = append(ruleFiles, rulesPath)
			} else {
				if debug {
					logger.Log.Debugf("invalid rule file: %v, detail: %v", rulesPath, errRet)
				}
				// os.Remove(rulesPath)
			}
		}
	}
	return ruleFiles
}

func InitRule(rulePath string, debug bool) (error) {
	files := TestRule(rulePath, debug)
	return initRule(files, debug)
}

func initRule(ruleFiles []string, debug bool) (error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		logger.Log.Panic(err)
	}
	for _, rulePath := range ruleFiles {
		// pass index file
		if strings.Contains(rulePath, "index") || strings.Contains(rulePath, "util") {
			continue
		}

		rulesObj, err := os.Open(rulePath)
		// logger.Log.Warnf("check Yara rule: %v, result: %v", rulePath, err)
		defer rulesObj.Close()
		if err == nil {
			paths := strings.Split(rulePath, "/")
			namespace := paths[len(paths)-2]
			//namespace := strings.Join(paths[0:len(paths)-2], "_")
			//namespace := strings.Join(strings.Fields(t), "_")
			err := compiler.AddFile(rulesObj, namespace)
			if debug {
				logger.Log.Printf("Compiling Yara rule: %v, result: %v", rulePath, err)
			}
		}
	}

	// Collect and compile Yara rules.
	rules, err := compiler.GetRules()
	if err == nil {
		// Save the compiled rules to a file.
		rules.Save("rules.db")

	}
	total := len(rules.GetRules())

	logger.Log.Printf("Init rules Done, total: %v rules, err: %v", total, err)
	return err
}
