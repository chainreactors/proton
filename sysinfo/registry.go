package sysinfo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	RegistryTypeNone                     = 0
	RegistryTypeString                   = 1
	RegistryTypeExpandString             = 2
	RegistryTypeBinary                   = 3
	RegistryTypeDWord                    = 4
	RegistryTypeDWordBigEndian           = 5
	RegistryTypeLink                     = 6
	RegistryTypeMultiString              = 7
	RegistryTypeResourceList             = 8
	RegistryTypeFullResourceDescriptor   = 9
	RegistryTypeResourceRequirementsList = 10
	RegistryTypeQWord                    = 11
)

const (
	DefaultRegistryMaxDepth      = 3
	DefaultRegistryMaxKeys       = 10000
	DefaultRegistryMaxValues     = 50000
	DefaultRegistryMaxValueBytes = 1 << 20
)

type RegistryTarget struct {
	Root     string
	Path     string
	MaxDepth int
}

type RegistryWalkOptions struct {
	Targets       []RegistryTarget
	Hives         []string
	MaxDepth      int
	MaxKeys       int
	MaxValues     int
	MaxValueBytes int
	IncludeBinary bool
}

type RegistryValue struct {
	Root          string
	KeyPath       string
	ValueName     string
	Type          uint32
	Data          []byte
	Hive          string
	Truncated     bool
	IncludeBinary bool
}

func DefaultRegistryWalkOptions() RegistryWalkOptions {
	return RegistryWalkOptions{
		Targets:       DefaultRegistryTargets(),
		MaxDepth:      DefaultRegistryMaxDepth,
		MaxKeys:       DefaultRegistryMaxKeys,
		MaxValues:     DefaultRegistryMaxValues,
		MaxValueBytes: DefaultRegistryMaxValueBytes,
	}
}

func DefaultRegistryTargets() []RegistryTarget {
	return []RegistryTarget{
		{Root: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\Run`, MaxDepth: 1},
		{Root: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`, MaxDepth: 1},
		{Root: "HKLM", Path: `Software\Microsoft\Windows\CurrentVersion\Run`, MaxDepth: 1},
		{Root: "HKLM", Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`, MaxDepth: 1},
		{Root: "HKLM", Path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, MaxDepth: 1},
		{Root: "HKCU", Path: `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, MaxDepth: 2},
		{Root: "HKCU", Path: `Software\Microsoft\Terminal Server Client\Servers`, MaxDepth: 2},
		{Root: "HKCU", Path: `Software\SimonTatham\PuTTY\Sessions`, MaxDepth: 3},
		{Root: "HKCU", Path: `Software\WinSCP 2\Sessions`, MaxDepth: 3},
		{Root: "HKLM", Path: `SYSTEM\CurrentControlSet\Services`, MaxDepth: 2},
	}
}

func ParseRegistryTarget(path string, maxDepth int) (RegistryTarget, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return RegistryTarget{}, fmt.Errorf("empty registry path")
	}
	normalized := strings.ReplaceAll(path, "/", `\`)
	parts := strings.SplitN(normalized, `\`, 2)
	if len(parts) != 2 {
		return RegistryTarget{}, fmt.Errorf("registry path must include root: %s", path)
	}
	root := NormalizeRegistryRoot(parts[0])
	if root == "" {
		return RegistryTarget{}, fmt.Errorf("unsupported registry root: %s", parts[0])
	}
	return RegistryTarget{Root: root, Path: strings.Trim(parts[1], `\`), MaxDepth: maxDepth}, nil
}

func NormalizeRegistryRoot(root string) string {
	switch strings.ToUpper(strings.TrimSpace(root)) {
	case "HKCU", "HKEY_CURRENT_USER":
		return "HKCU"
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "HKLM"
	case "HKU", "HKEY_USERS":
		return "HKU"
	case "HKCR", "HKEY_CLASSES_ROOT":
		return "HKCR"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return "HKCC"
	default:
		return ""
	}
}

func (v RegistryValue) Label() string {
	valueName := v.ValueName
	if valueName == "" {
		valueName = "(Default)"
	}
	if v.Hive != "" {
		return fmt.Sprintf("registry-hive:%s:%s:%s", v.Hive, v.KeyPath, valueName)
	}
	if v.KeyPath == "" {
		return fmt.Sprintf("registry:%s:%s", v.Root, valueName)
	}
	return fmt.Sprintf("registry:%s\\%s:%s", v.Root, v.KeyPath, valueName)
}

func (v RegistryValue) Record() []byte {
	valueName := v.ValueName
	if valueName == "" {
		valueName = "(Default)"
	}
	root := v.Root
	if root == "" && v.Hive != "" {
		root = "HIVE"
	}
	var b strings.Builder
	if v.Hive != "" {
		b.WriteString("hive=")
		b.WriteString(v.Hive)
		b.WriteByte('\n')
	}
	b.WriteString("path=")
	if root != "" {
		b.WriteString(root)
		if v.KeyPath != "" {
			b.WriteByte('\\')
		}
	}
	b.WriteString(v.KeyPath)
	b.WriteByte('\n')
	b.WriteString("name=")
	b.WriteString(valueName)
	b.WriteByte('\n')
	b.WriteString("type=")
	b.WriteString(RegistryTypeName(v.Type))
	b.WriteByte('\n')
	if v.Truncated {
		b.WriteString("truncated=true\n")
	}
	b.WriteString("data=")
	b.WriteString(FormatRegistryData(v.Type, v.Data, v.IncludeBinary))
	b.WriteByte('\n')
	return []byte(b.String())
}

func RegistryTypeName(typ uint32) string {
	switch typ {
	case RegistryTypeNone:
		return "REG_NONE"
	case RegistryTypeString:
		return "REG_SZ"
	case RegistryTypeExpandString:
		return "REG_EXPAND_SZ"
	case RegistryTypeBinary:
		return "REG_BINARY"
	case RegistryTypeDWord:
		return "REG_DWORD"
	case RegistryTypeDWordBigEndian:
		return "REG_DWORD_BIG_ENDIAN"
	case RegistryTypeLink:
		return "REG_LINK"
	case RegistryTypeMultiString:
		return "REG_MULTI_SZ"
	case RegistryTypeResourceList:
		return "REG_RESOURCE_LIST"
	case RegistryTypeFullResourceDescriptor:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case RegistryTypeResourceRequirementsList:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case RegistryTypeQWord:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_%d", typ)
	}
}

func FormatRegistryData(typ uint32, data []byte, includeBinary bool) string {
	switch typ {
	case RegistryTypeString, RegistryTypeExpandString, RegistryTypeLink:
		return decodeRegistryUTF16(data)
	case RegistryTypeMultiString:
		return strings.Join(decodeRegistryMultiString(data), ";")
	case RegistryTypeDWord:
		if len(data) >= 4 {
			v := binary.LittleEndian.Uint32(data[:4])
			return fmt.Sprintf("%d (0x%08x)", v, v)
		}
	case RegistryTypeDWordBigEndian:
		if len(data) >= 4 {
			v := binary.BigEndian.Uint32(data[:4])
			return fmt.Sprintf("%d (0x%08x)", v, v)
		}
	case RegistryTypeQWord:
		if len(data) >= 8 {
			v := binary.LittleEndian.Uint64(data[:8])
			return fmt.Sprintf("%d (0x%016x)", v, v)
		}
	}
	if includeBinary {
		return hex.EncodeToString(data)
	}
	return strings.Join(extractRegistryStrings(data), " ")
}

func decodeRegistryUTF16(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u16 := make([]uint16, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			break
		}
		u16 = append(u16, ch)
	}
	return string(utf16.Decode(u16))
}

func decodeRegistryMultiString(data []byte) []string {
	var result []string
	var current []uint16
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			if len(current) == 0 {
				break
			}
			result = append(result, string(utf16.Decode(current)))
			current = nil
			continue
		}
		current = append(current, ch)
	}
	if len(current) > 0 {
		result = append(result, string(utf16.Decode(current)))
	}
	return result
}

func extractRegistryStrings(data []byte) []string {
	var out []string
	var ascii []byte
	flushASCII := func() {
		if len(ascii) >= 4 {
			out = append(out, string(ascii))
		}
		ascii = nil
	}
	for _, b := range data {
		if b >= 32 && b <= 126 {
			ascii = append(ascii, b)
		} else {
			flushASCII()
		}
	}
	flushASCII()

	var utf []uint16
	flushUTF := func() {
		if len(utf) >= 4 {
			out = append(out, string(utf16.Decode(utf)))
		}
		utf = nil
	}
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch >= 32 && ch <= 126 {
			utf = append(utf, ch)
		} else {
			flushUTF()
		}
	}
	flushUTF()
	return out
}

func applyRegistryDefaults(opts RegistryWalkOptions) RegistryWalkOptions {
	if len(opts.Targets) == 0 && len(opts.Hives) == 0 {
		opts.Targets = DefaultRegistryTargets()
	}
	if opts.MaxDepth < 0 {
		opts.MaxDepth = 0
	}
	if opts.MaxDepth == 0 {
		opts.MaxDepth = DefaultRegistryMaxDepth
	}
	if opts.MaxKeys <= 0 {
		opts.MaxKeys = DefaultRegistryMaxKeys
	}
	if opts.MaxValues <= 0 {
		opts.MaxValues = DefaultRegistryMaxValues
	}
	if opts.MaxValueBytes <= 0 {
		opts.MaxValueBytes = DefaultRegistryMaxValueBytes
	}
	for i := range opts.Targets {
		opts.Targets[i].Root = NormalizeRegistryRoot(opts.Targets[i].Root)
		if opts.Targets[i].MaxDepth <= 0 {
			opts.Targets[i].MaxDepth = opts.MaxDepth
		}
	}
	return opts
}
