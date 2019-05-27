package msad

import "github.com/go-ldap/ldap"

func (s *MSAd) Authenticate(account, password string) (*Entry, error) {
	conn, err := s.open(false)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	filter := &EntryFilter{
		Account: account,
	}
	loginName, _ := filter.getAccount(s.Cfg.Base, account)
	err = conn.Bind(loginName, password)
	if err != nil {
		return nil, err
	}

	searchFilter := filter.GetFilter(s.Cfg.Base, ClassUser)
	searchRequest := ldap.NewSearchRequest(
		s.Cfg.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		searchFilter,
		[]string{"dn", "cn"},
		nil,
	)
	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	entryPath := newEntryPath(s.Cfg.Base)
	entry := &Entry{}
	for _, item := range searchResult.Entries {
		entry.Path = entryPath.Path(item.DN)
		entry.Name = item.GetAttributeValue("cn")
		break
	}

	return entry, nil
}
