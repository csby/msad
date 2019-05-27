package msad

import (
	"bytes"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"sort"
	"strings"
)

type Entry struct {
	Path        string `json:"path" note:"路径"`
	Name        string `json:"name" note:"名称"`
	Class       string `json:"entryClass" note:"类别: user, group, container, organizationalUnit等"`
	Description string `json:"description" note:"描述"`
	Mail        string `json:"mail" note:"电子邮箱"`
	Info        string `json:"info" note:"注释"`
	Street      string `json:"street" note:"街道"`

	Children []*Entry `json:"children,omitempty" note:"子对象"`
}

type EntryCollection []*Entry

func (s EntryCollection) Len() int      { return len(s) }
func (s EntryCollection) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s EntryCollection) Less(i, j int) bool {
	a, _ := utf8ToGBK(strings.ToLower(s[i].Name))
	b, _ := utf8ToGBK(strings.ToLower(s[j].Name))
	bLen := len(b)
	for idx, chr := range a {
		if idx > bLen-1 {
			return false
		}
		if chr != b[idx] {
			return chr < b[idx]
		}
	}
	return true

	//return strings.ToLower(p[i].Name) <  strings.ToLower(p[j].Name)
}
func (s EntryCollection) Sort() {
	sort.Stable(s)
}

func utf8ToGBK(src string) ([]byte, error) {
	GB18030 := simplifiedchinese.All[0]
	return ioutil.ReadAll(transform.NewReader(bytes.NewReader([]byte(src)), GB18030.NewEncoder()))
}
