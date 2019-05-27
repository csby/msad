package msad

type EntryOrganizationUnitCreate struct {
	Name        string `json:"name" note:"名称，development"`
	Parent      *Entry `json:"parent" note:"父级容器, 空则默认在Users容器"`
	Description string `json:"description" note:"描述"`
	Street      string `json:"street" note:"街道"`
}
