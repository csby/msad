package msad

import (
	"fmt"
	"strings"
)

type EntryFilter struct {
	Account string `json:"account" note:"账号, 例如: Administrator"`
	Path    string `json:"path" note:"路径, 例如: CN=Administrator,CN=Users"`
	GUID    string `json:"guid" note:"GUID"`
	SID     string `json:"sid" note:"SID"`
}

func (s *EntryFilter) GetFilter(base string, objectClass string) string {
	sb := strings.Builder{}
	if len(objectClass) > 0 {
		sb.WriteString(fmt.Sprintf("(objectClass=%s)", objectClass))
	}
	if len(s.SID) > 0 {
		sb.WriteString(fmt.Sprintf("(objectSid=%s)", s.SID))
	}
	if len(s.GUID) > 0 {
		sb.WriteString(fmt.Sprintf("(objectGUID=%s)", s.GUID))
	}
	if len(s.Path) > 0 {
		entryPath := newEntryPath(base)
		sb.WriteString(fmt.Sprintf("(distinguishedName=%s)", entryPath.DistinguishedName(s.Path)))
	}
	if len(s.Account) > 0 {
		_, samName := s.getAccount(base, s.Account)
		sb.WriteString(fmt.Sprintf("(sAMAccountName=%s)", samName))
	}

	return fmt.Sprintf("(&%s)", sb.String())
}

func (s *EntryFilter) getAccount(base string, account string) (loginName, samAccountName string) {
	loginName = account
	samAccountName = account

	if index := strings.LastIndex(account, "\\"); index != -1 {
		samAccountName = account[index+1:]
	} else if index := strings.Index(account, "@"); index != -1 {
		samAccountName = account[:index]
	} else {
		domain := s.getDomain(base)
		if domain != "" {
			loginName = fmt.Sprintf("%s@%s", account, domain)
		}
	}

	return
}

func (s *EntryFilter) getDomain(base string) string {
	if len(base) < 1 {
		return ""
	}

	items := strings.Split(base, ",")
	itemCount := len(items)
	if itemCount < 1 {
		return ""
	}
	item := strings.Split(items[0], "=")
	if len(item) < 2 {
		return ""
	}
	sb := &strings.Builder{}
	sb.WriteString(strings.TrimSpace(item[1]))

	for index := 1; index < itemCount; index++ {
		item := strings.Split(items[index], "=")
		if len(item) < 2 {
			break
		}
		sb.WriteString(".")
		sb.WriteString(strings.TrimSpace(item[1]))
	}

	return sb.String()
}
