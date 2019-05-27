package msad

import (
	"fmt"
	"github.com/go-ldap/ldap"
	"strings"
)

func (s *MSAd) GetChildren(filter *EntryFilter, childClass string) ([]*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	parent, err := s.getEntry(conn, filter)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	sb := strings.Builder{}
	if len(childClass) > 0 {
		sb.WriteString(fmt.Sprintf("(objectClass=%s)", childClass))
	}
	sb.WriteString(fmt.Sprintf("(msDS-parentdistname=%s)", entryPath.DistinguishedName(parent.Path)))

	searchFilter := fmt.Sprintf("(&%s)", sb.String())
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "objectClass", "description", "mail", "info", "street"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	results := make(EntryCollection, 0)
	for _, item := range searchResult.Entries {
		result := &Entry{
			Name: entryPath.Name(item.DN),
			Path: entryPath.Path(item.DN),
		}
		result.Class = s.lastElement(item.GetAttributeValues("objectClass"))
		result.Description = item.GetAttributeValue("description")
		result.Mail = item.GetAttributeValue("mail")
		result.Info = item.GetAttributeValue("info")
		result.Street = item.GetAttributeValue("street")
		results = append(results, result)
	}
	results.Sort()

	return results, nil
}

func (s *MSAd) CreateOrganizationUnit(ou *EntryOrganizationUnitCreate) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if ou.Name == "" {
		return nil, fmt.Errorf("名称为空")
	}
	entryPath := newEntryPath(s.Cfg.Base)
	groupDn := entryPath.DistinguishedName(fmt.Sprintf("OU=%s,CN=Users", ou.Name))
	if ou.Parent != nil {
		filter := &EntryFilter{
			Path: ou.Parent.Path,
		}
		parentEntry, err := s.getEntry(conn, filter)
		if err != nil {
			return nil, fmt.Errorf("父级容器(%s)不存在", ou.Parent.Path)
		}
		groupDn = entryPath.DistinguishedName(fmt.Sprintf("OU=%s,%s", ou.Name, parentEntry.Path))
	}
	filter := &EntryFilter{
		Path: entryPath.Path(groupDn),
	}
	_, err = s.getEntry(conn, filter)
	if err == nil {
		return nil, fmt.Errorf("名称(%s)已存在", filter.Path)
	}

	addRequest := ldap.NewAddRequest(groupDn, nil)
	addRequest.Attribute("objectClass", []string{ClassOrganizationalUnit})
	addRequest.Attribute("description", []string{ou.Description})
	addRequest.Attribute("street", []string{ou.Street})

	err = conn.Add(addRequest)
	if err != nil {
		return nil, err
	}

	groupEntry := &Entry{
		Path:        entryPath.Path(groupDn),
		Name:        entryPath.Name(groupDn),
		Class:       ClassOrganizationalUnit,
		Description: ou.Description,
		Street:      ou.Street,
	}

	return groupEntry, nil
}

func (s *MSAd) DeleteOrganizationUnit(ou *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	ouEntry, err := s.getEntry(conn, ou)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	ouDn := entryPath.DistinguishedName(ouEntry.Path)

	delRequest := ldap.NewDelRequest(ouDn, nil)
	err = conn.Del(delRequest)
	if err != nil {
		return nil, err
	}

	return ouEntry, nil
}
