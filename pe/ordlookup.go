package pe

import (
	"strings"
	"fmt"
)

var OrdNames = map[string]map[uint64]string {
	"ws2_32.dll": WS2_32_ORD_NAMES,
	"wsock32.dll": WS2_32_ORD_NAMES,
	"oleaut32.dll": OLEAUT_32_ORD_NAMES,
}

func OrdLookup(libname string, ord uint64, makeName bool) string {
	names, ok := OrdNames[strings.ToLower(libname)]
	if ok {
		if name, ok := names[ord]; ok {
			return name
		}
	}
	if makeName {
		return fmt.Sprintf("ord%d", ord)
	} else {
		return ""
	}
}