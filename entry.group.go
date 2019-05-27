package msad

type EntryGroupCreate struct {
	Name        string `json:"name" note:"名称，admins"`
	Parent      *Entry `json:"parent" note:"父级容器, 空则默认在Users容器"`
	Description string `json:"description" note:"描述"`
	Mail        string `json:"mail" note:"电子邮箱"`
	Info        string `json:"info" note:"注释"`
}
