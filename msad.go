package msad

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap"
	"golang.org/x/text/encoding/unicode"
	"strings"
)

type MSAd struct {
	Cfg *Configure
}

func (s *MSAd) GetObjects(objectCategory, objectClass string) ([]*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(&(objectCategory=%s)(objectClass=%s)))", objectCategory, objectClass),
		[]string{"dn"},
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	entryPath := newEntryPath(s.Cfg.Base)
	results := make(EntryCollection, 0)
	for _, item := range searchResult.Entries {
		result := &Entry{}
		result.Path = entryPath.Path(item.DN)
		result.Name = entryPath.Name(item.DN)
		results = append(results, result)
	}
	results.Sort()

	return results, nil
}

func (s *MSAd) GetEntry(filter *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return s.getEntry(conn, filter)
}

func (s *MSAd) getObjectBySid(conn *ldap.Conn, objectSid string) (*Entry, error) {
	if len(objectSid) < 1 {
		return nil, fmt.Errorf("invalid objectSid")
	}

	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectSid=%s))", objectSid), // The filter to apply
		[]string{"dn"}, // A list attributes to retrieve
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	entryPath := newEntryPath(s.Cfg.Base)
	for _, item := range searchResult.Entries {
		entry := &Entry{}
		entry.Path = entryPath.Path(item.DN)
		entry.Name = entryPath.Name(item.DN)

		return entry, nil
	}

	return nil, nil
}

func (s *MSAd) getEntry(conn *ldap.Conn, filter *EntryFilter) (*Entry, error) {
	searchFilter := filter.GetFilter(s.Cfg.Base, "")
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "objectClass", "description"}, // A list attributes to retrieve
		nil,
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) < 1 {
		return nil, fmt.Errorf("not found: %s", searchFilter)
	}

	entryPath := newEntryPath(s.Cfg.Base)
	for _, item := range searchResult.Entries {
		entry := &Entry{}
		entry.Path = entryPath.Path(item.DN)
		entry.Name = entryPath.Name(item.DN)
		entry.Class = s.lastElement(item.GetAttributeValues("objectClass"))
		entry.Description = item.GetAttributeValue("description")

		return entry, nil
	}

	return nil, nil
}

func (s *MSAd) open(bind bool) (*ldap.Conn, error) {
	if s.Cfg == nil {
		return nil, fmt.Errorf("cfg is nill")
	}

	// default ports: 389 or 636(tls)
	host := s.Cfg.Host
	port := s.Cfg.Port
	if port == 0 {
		port = 636
	}

	tlsConfig := &tls.Config{
		//MaxVersion: tls.VersionTLS10,
		InsecureSkipVerify: true,
	}
	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)
	if err != nil {
		return nil, err
	}

	//cs, ok := conn.TLSConnectionState()
	//if !ok {
	//	conn.Close()
	//	return nil, fmt.Errorf("TLSConnectionState not ok")
	//}
	//fmt.Println("cs version:", cs.Version)

	if bind {
		err = conn.Bind(s.Cfg.Auth.Account, s.Cfg.Auth.Password)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func (s *MSAd) decodeSID(sid []byte) string {
	if len(sid) < 28 {
		return ""
	}
	strSid := strings.Builder{}
	strSid.WriteString("S-")

	revision := int(sid[0])
	strSid.WriteString(fmt.Sprint(revision))

	countSubAuths := int(sid[1] & 0xFF)
	authority := int(0)
	for i := 2; i <= 7; i++ {
		shift := uint(8 * (5 - (i - 2)))
		authority |= int(sid[i]) << shift
	}
	strSid.WriteString("-")
	strSid.WriteString(fmt.Sprintf("%x", authority))

	offset := 8
	size := 4
	for j := 0; j < countSubAuths; j++ {
		subAuthority := 0
		for k := 0; k < size; k++ {
			subAuthority |= (int(sid[offset+k]) & 0xFF) << uint(8*k)
		}
		strSid.WriteString("-")
		strSid.WriteString(fmt.Sprint(subAuthority))
		offset += size
	}

	return strSid.String()
}

func (s *MSAd) decodeGUID(uuid []byte) string {
	if len(uuid) < 16 {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func (s *MSAd) lastElement(values []string) string {
	count := len(values)
	if count > 0 {
		return values[count-1]
	} else {
		return ""
	}
}

// https://msdn.microsoft.com/en-us/library/cc223248.aspx
func (s *MSAd) encodePassword(password string) (string, error) {
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	return utf16.NewEncoder().String(fmt.Sprintf(`"%s"`, password))
}
