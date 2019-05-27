package msad

import (
	"fmt"
	"strconv"
)

type EntryUserCreate struct {
	Account  string `json:"account" note:"账号，如zhang.san"`
	Password string `json:"password" note:"密码"`
	Name     string `json:"name" note:"姓名，如张三"`
	Parent   *Entry `json:"parent" note:"父级容器, 空则默认在Users容器"`
	Manager  *Entry `json:"manager" note:"主管"`
}

type EntryUserControl struct {
	Disable            bool `json:"disable" note:"账户已禁用"`
	DontExpirePassword bool `json:"dontExpirePassword" note:"密码永不过期"`
}

func (s *EntryUserControl) ToValue(value string) (string, error) {
	val, err := strconv.Atoi(value)
	if err != nil {
		return "", err
	}

	if s.Disable {
		val |= ACCOUNTDISABLE
	} else {
		val &= ^ACCOUNTDISABLE
	}

	if s.DontExpirePassword {
		val |= DONT_EXPIRE_PASSWD
	} else {
		val &= ^DONT_EXPIRE_PASSWD
	}

	return fmt.Sprint(val), nil
}

func (s *EntryUserControl) FromValue(value string) error {
	val, err := strconv.Atoi(value)
	if err != nil {
		return err
	}

	if (val & ACCOUNTDISABLE) == 0 {
		s.Disable = false
	} else {
		s.Disable = true
	}

	if (val & DONT_EXPIRE_PASSWD) == 0 {
		s.DontExpirePassword = false
	} else {
		s.DontExpirePassword = true
	}

	return nil
}
