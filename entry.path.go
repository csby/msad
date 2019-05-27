package msad

import (
	"fmt"
	"strings"
)

type EntryPath struct {
	base       string
	baseLength int
}

func newEntryPath(base string) *EntryPath {
	return &EntryPath{
		base:       base,
		baseLength: len(fmt.Sprintf(",%s", base)),
	}
}

func (s *EntryPath) Path(path string) string {
	pathLen := len(path)
	if pathLen > s.baseLength {
		return path[0 : pathLen-s.baseLength]
	}

	return path
}

func (s *EntryPath) DistinguishedName(path string) string {
	return fmt.Sprintf("%s,%s", path, s.base)
}

func (s *EntryPath) Name(path string) string {
	vs := strings.Split(path, ",")
	if len(vs) < 1 {
		return ""
	}
	ns := strings.Split(vs[0], "=")
	if len(ns) < 2 {
		return ""
	}

	return ns[1]
}
