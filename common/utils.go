package common

import (
	"fmt"
	"os"
)

type utils struct {
}

var Utils = utils{}

func (receiver utils) GetIpDataPath() (dbPath string) {
	dir, _ := os.Getwd()
	println("dir", dir)
	fmt.Println("dir != \"/\"", dir != "/")
	if dir != "/" {
		dbPath = dir + "/data"
	} else {
		dbPath = "/data"
	}
	dbPath = receiver.GetEnv("DB_PATH", "")
	return dbPath
}

func (receiver utils) GetRootPath() (root string) {
	dir, _ := os.Getwd()
	fmt.Println("dir != \"/\"", dir != "/")
	if dir != "/" {
		root = dir
	} else {
		root = ""
	}
	println("root", root)
	return root
}
func (receiver utils) GetTemplatePath() (root string) {
	return receiver.GetRootPath() + "/templates"
}

func (receiver utils) GetEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}
