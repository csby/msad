package msad

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMSAd_GetObjects(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	objectCategory := CategoryPerson
	objectClass := ClassUser
	objects, err := sdk.GetObjects(objectCategory, objectClass)
	if err != nil {
		t.Fatal(err)
	}
	objectCount := len(objects)
	t.Log("objects count:", objectCount)
	for index := 0; index < objectCount; index++ {
		item := objects[index]
		t.Log(index+1, "-", item.Name, ":", item.Path)
	}
}

func TestMSAd_GetEntry(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	filter := &EntryFilter{
		Account: "Administrator",
	}
	entry, err := sdk.GetEntry(filter)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_GetUserGroups(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	account := "Administrator"
	filter := &EntryFilter{
		Account: account,
	}
	groups, err := sdk.GetUserGroups(filter)
	if err != nil {
		t.Fatal(err)
	}
	groupCount := len(groups)
	t.Log("groups count:", groupCount)
	for index := 0; index < groupCount; index++ {
		item := groups[index]
		t.Log(index+1, "-", item.Name, "(", item.Class, ") :", item.Path)
	}
}

func TestMSAd_GetUserManager(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	filter := &EntryFilter{
		Account: "Administrator",
	}
	entry, err := sdk.GetUserManager(filter)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_SetUserManager(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "Administrator",
	}
	manager := &EntryFilter{
		Account: "test",
	}
	entry, err := sdk.SetUserManager(user, manager)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_GetUserDirectReports(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	filter := &EntryFilter{
		Account: "Administrator",
	}
	entries, err := sdk.GetUserDirectReports(filter)
	if err != nil {
		t.Fatal(err)
	}
	count := len(entries)
	t.Log("count:", count)
	for index := 0; index < count; index++ {
		item := entries[index]
		t.Log(index+1, "-", item.Name, "(", item.Class, ") :", item.Path)
	}
}

func TestMSAd_SetUserPassword(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "Administrator",
	}
	password := ""
	entry, err := sdk.SetUserPassword(user, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_ChangeUserPassword(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "Administrator",
	}
	oldPassword := ""
	nowPassword := ""
	err := sdk.ChangeUserPassword(user, oldPassword, nowPassword)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMSAd_CreateUser(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryUserCreate{
		Account:  "ot",
		Password: "Test20",
		Name:     "测试",
		Parent: &Entry{
			Path: "OU=保留账号",
		},
		Manager: &Entry{
			Path: "CN=Administrator,CN=Users",
		},
	}
	entry, err := sdk.CreateUser(user)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_DeleteUser(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Path: "CN=测试,OU=保留账号",
	}
	entry, err := sdk.DeleteUser(user)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_GetUserControl(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "ot",
	}
	entry, err := sdk.GetUserControl(user)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%#v", entry))
}

func TestMSAd_SetUserControl(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "ot",
	}
	control := &EntryUserControl{
		Disable:            false,
		DontExpirePassword: true,
	}
	entry, err := sdk.SetUserControl(user, control)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("%#v", entry))
}

func TestMSAd_SetUserVpnEnable(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "ot",
	}
	enable := false
	err := sdk.SetUserVpnEnable(user, enable)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMSAd_GetUserVpnEnable(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	user := &EntryFilter{
		Account: "ot",
	}
	enable, err := sdk.GetUserVpnEnable(user)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("enable:", enable)
}

func TestMSAd_GetCroupMembers(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	filter := &EntryFilter{
		Account: "Domain Admins",
	}
	members, err := sdk.GetCroupMembers(filter, "")
	if err != nil {
		t.Fatal(err)
	}
	memberCount := len(members)
	t.Log("member count:", memberCount)
	for index := 0; index < memberCount; index++ {
		item := members[index]
		t.Log(index+1, "-", item.Name, ":", item.Path)
	}

}

func TestMSAd_CreateGroup(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	group := &EntryGroupCreate{
		Name: "gt",
		Parent: &Entry{
			Path: "OU=保留账号",
		},
		Description: "description",
		Mail:        "mail",
		Info:        "info",
	}
	entry, err := sdk.CreateGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_DeleteGroup(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	group := &EntryFilter{
		Path: "CN=gt,OU=保留账号",
	}
	entry, err := sdk.DeleteGroup(group)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_AddGroupMember(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	group := &EntryFilter{
		Path: "CN=gt,OU=保留账号",
	}
	member := &EntryFilter{
		Account: "Administrator",
	}

	entry, err := sdk.AddGroupMember(group, member)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_RemoveGroupMember(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	group := &EntryFilter{
		Path: "CN=gt,OU=保留账号",
	}
	member := &EntryFilter{
		Account: "Administrator",
	}

	entry, err := sdk.RemoveGroupMember(group, member)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_GetChildren(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	filter := &EntryFilter{
		Path: "OU=共享目录",
	}
	children, err := sdk.GetChildren(filter, "")
	if err != nil {
		t.Fatal(err)
	}
	count := len(children)
	t.Log("child count:", count)
	for index := 0; index < count; index++ {
		item := children[index]
		t.Log(index+1, "-", fmt.Sprintf("%+v", item))
	}

}

func TestMSAd_CreateOrganizationUnit(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	ou := &EntryOrganizationUnitCreate{
		Name: "ot",
		Parent: &Entry{
			Path: "OU=保留账号",
		},
		Description: "description",
		Street:      "street\r\n192.168.1.1",
	}
	entry, err := sdk.CreateOrganizationUnit(ou)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func TestMSAd_DeleteOrganizationUnit(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	ou := &EntryFilter{
		Path: "OU=ot,OU=保留账号",
	}
	entry, err := sdk.DeleteOrganizationUnit(ou)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(entry.Name, "(", entry.Class, ") :", entry.Path)
}

func getConfigure() *Configure {
	goPath := os.Getenv("GOPATH")
	paths := strings.Split(goPath, string(os.PathListSeparator))
	if len(paths) > 1 {
		goPath = paths[0]

		_, file, _, _ := runtime.Caller(0)
		fileDir := strings.ToLower(filepath.Dir(file))
		for _, path := range paths {
			if strings.HasPrefix(fileDir, strings.ToLower(path)) {
				goPath = path
				break
			}
		}
	}
	cfgPath := filepath.Join(goPath, "tmp", "cfg", "msad_test.json")
	cfg := &Configure{
		Host: "example.com",
		Port: 636,
		Base: "dc=examle,dc=com",
		Auth: ConfigureAuth{
			Account: "Administrator",
		},
	}
	_, err := os.Stat(cfgPath)
	if os.IsNotExist(err) {
		err = cfg.SaveToFile(cfgPath)
		if err != nil {
			fmt.Println("generate configure file fail: ", err)
		}
	} else {
		err = cfg.LoadFromFile(cfgPath)
		if err != nil {
			fmt.Println("load configure file fail: ", err)
		}
	}

	return cfg
}

func TestMSAd_encodePassword(t *testing.T) {
	sdk := &MSAd{Cfg: getConfigure()}

	// 0x6E 0x65 0x77
	rawPwd := "new"
	rawBytes := []byte(rawPwd)
	fmt.Print("r: ")
	for _, v := range rawBytes {
		fmt.Printf("0x%X ", v)
	}
	fmt.Println("")

	// 0x22 0x00 0x6E 0x00 0x65 0x00 0x77 0x00 0x22 0x00
	encodedPwd, err := sdk.encodePassword(rawPwd)
	if err != nil {
		t.Fatal(err)
	}

	encodedBytes := []byte(encodedPwd)
	fmt.Print("e: ")
	for _, v := range encodedBytes {
		fmt.Printf("0x%X ", v)
	}
	fmt.Println("")

}
