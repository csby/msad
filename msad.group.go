package msad

import (
	"fmt"
	"github.com/go-ldap/ldap"
	"strings"
)

func (s *MSAd) GetCroupMembers(filter *EntryFilter, memberClass string) ([]*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := filter.GetFilter(s.Cfg.Base, ClassGroup)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"member"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	entryPath := newEntryPath(s.Cfg.Base)
	results := make(EntryCollection, 0)
	for _, item := range searchResult.Entries {
		attributes := item.GetAttributeValues("member")
		for _, attribute := range attributes {
			name := entryPath.Name(attribute)
			if len(name) < 1 {
				continue
			}

			result := &Entry{
				Name: entryPath.Name(attribute),
				Path: entryPath.Path(attribute),
			}
			results = append(results, result)
		}
	}
	results.Sort()

	return results, nil
}

func (s *MSAd) CreateGroup(group *EntryGroupCreate) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if group.Name == "" {
		return nil, fmt.Errorf("名称为空")
	}
	filter := &EntryFilter{
		Account: group.Name,
	}
	_, err = s.getEntry(conn, filter)
	if err == nil {
		return nil, fmt.Errorf("名称(%s)已存在", group.Name)
	}
	entryPath := newEntryPath(s.Cfg.Base)
	groupDn := entryPath.DistinguishedName(fmt.Sprintf("CN=%s,CN=Users", group.Name))
	if group.Parent != nil {
		filter = &EntryFilter{
			Path: group.Parent.Path,
		}
		parentEntry, err := s.getEntry(conn, filter)
		if err != nil {
			return nil, fmt.Errorf("父级容器(%s)不存在", group.Parent.Path)
		}
		groupDn = entryPath.DistinguishedName(fmt.Sprintf("CN=%s,%s", group.Name, parentEntry.Path))
	}
	filter = &EntryFilter{
		Path: entryPath.Path(groupDn),
	}
	_, err = s.getEntry(conn, filter)
	if err == nil {
		return nil, fmt.Errorf("名称(%s)已存在", filter.Path)
	}

	addRequest := ldap.NewAddRequest(groupDn, nil)
	addRequest.Attribute("objectClass", []string{ClassGroup})
	addRequest.Attribute("sAMAccountName", []string{group.Name})
	addRequest.Attribute("description", []string{group.Description})
	addRequest.Attribute("mail", []string{group.Mail})
	addRequest.Attribute("info", []string{group.Info})

	err = conn.Add(addRequest)
	if err != nil {
		return nil, err
	}

	groupEntry := &Entry{
		Path:        entryPath.Path(groupDn),
		Name:        entryPath.Name(groupDn),
		Class:       ClassGroup,
		Description: group.Description,
		Mail:        group.Mail,
		Info:        group.Info,
	}

	return groupEntry, nil
}

func (s *MSAd) DeleteGroup(group *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	groupEntry, err := s.getEntry(conn, group)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	groupDn := entryPath.DistinguishedName(groupEntry.Path)

	delRequest := ldap.NewDelRequest(groupDn, nil)
	err = conn.Del(delRequest)
	if err != nil {
		return nil, err
	}

	return groupEntry, nil
}

func (s *MSAd) AddGroupMember(group, member *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := group.GetFilter(s.Cfg.Base, ClassGroup)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "member"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) < 1 {
		return nil, fmt.Errorf("group(%s) not exist", searchFilter)
	}

	groupDn := ""
	members := make([]string, 0)
	for _, item := range searchResult.Entries {
		groupDn = item.DN
		members = item.GetAttributeValues("member")
		break
	}

	memberEntry, err := s.getEntry(conn, member)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	memberDn := entryPath.DistinguishedName(memberEntry.Path)
	members = append(members, memberDn)

	modifyRequest := ldap.NewModifyRequest(groupDn, nil)
	modifyRequest.Replace("member", members)

	err = conn.Modify(modifyRequest)
	if err != nil {
		return nil, err
	}

	return memberEntry, nil
}

func (s *MSAd) RemoveGroupMember(group, member *EntryFilter) (*Entry, error) {
	conn, err := s.open(true)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	searchFilter := group.GetFilter(s.Cfg.Base, ClassGroup)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "member"}, // A list attributes to retrieve
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) < 1 {
		return nil, fmt.Errorf("group(%s) not exist", searchFilter)
	}

	groupDn := ""
	members := make([]string, 0)
	for _, item := range searchResult.Entries {
		groupDn = item.DN
		members = item.GetAttributeValues("member")
		break
	}

	memberEntry, err := s.getEntry(conn, member)
	if err != nil {
		return nil, err
	}
	entryPath := newEntryPath(s.Cfg.Base)
	memberDn := entryPath.DistinguishedName(memberEntry.Path)

	newMembers := make([]string, 0)
	for _, item := range members {
		if strings.ToLower(item) == strings.ToLower(memberDn) {
			continue
		}

		newMembers = append(newMembers, item)
	}

	modifyRequest := ldap.NewModifyRequest(groupDn, nil)
	modifyRequest.Replace("member", newMembers)

	err = conn.Modify(modifyRequest)
	if err != nil {
		return nil, err
	}

	return memberEntry, nil
}
