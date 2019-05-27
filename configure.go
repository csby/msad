package msad

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

type Configure struct {
	Host string        `json:"host" note:"主机地址，如192.168.100.1或example.com"`
	Port int           `json:"port" note:"主机TLS端口，如636"`
	Base string        `json:"base" note:"根域信息，如dc=example,dc=com"`
	Auth ConfigureAuth `json:"auth" note:"授权信息"`
}

type ConfigureAuth struct {
	Account  string `json:"account" note:"授权账号，如Administrator"`
	Password string `json:"password" note:"账号秘密"`
}

func (s *Configure) SaveToFile(filePath string) error {
	bytes, err := json.MarshalIndent(s, "", "    ")
	if err != nil {
		return err
	}

	fileFolder := filepath.Dir(filePath)
	_, err = os.Stat(fileFolder)
	if os.IsNotExist(err) {
		os.MkdirAll(fileFolder, 0777)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = fmt.Fprint(file, string(bytes[:]))

	return err
}

func (s *Configure) LoadFromFile(filePath string) error {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, s)
}
