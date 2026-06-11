//go:build windows

package sysinfo

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	errorNoMoreItems = 259
)

var modoffreg = windows.NewLazySystemDLL("offreg.dll")

type registryWalkState struct {
	opts   RegistryWalkOptions
	keys   int
	values int
}

func WalkRegistry(opts RegistryWalkOptions, cb func(RegistryValue) error) error {
	opts = applyRegistryDefaults(opts)
	state := &registryWalkState{opts: opts}

	var firstErr error
	for _, target := range opts.Targets {
		if target.Root == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("empty registry root for path %s", target.Path)
			}
			continue
		}
		if err := walkLiveRegistryTarget(state, target, cb); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if len(opts.Hives) > 0 {
		offreg, err := loadOfflineRegistry()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else {
			for _, hive := range opts.Hives {
				if err := walkOfflineRegistryHive(state, offreg, hive, cb); err != nil && firstErr == nil {
					firstErr = err
				}
			}
		}
	}

	return firstErr
}

func walkLiveRegistryTarget(state *registryWalkState, target RegistryTarget, cb func(RegistryValue) error) error {
	rootKey, err := registryRootKey(target.Root)
	if err != nil {
		return err
	}

	var key registry.Key
	closeKey := false
	if target.Path == "" {
		key = rootKey
	} else {
		key, err = registry.OpenKey(rootKey, target.Path, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) || errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
				return nil
			}
			return err
		}
		closeKey = true
	}
	if closeKey {
		defer key.Close()
	}

	fullPath := strings.Trim(target.Path, `\`)
	return walkLiveRegistryKey(state, target.Root, key, fullPath, 0, target.MaxDepth, cb)
}

func walkLiveRegistryKey(state *registryWalkState, root string, key registry.Key, keyPath string, depth, maxDepth int, cb func(RegistryValue) error) error {
	if !state.takeKey() {
		return nil
	}

	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range valueNames {
			if !state.takeValue() {
				return nil
			}
			typ, data, truncated, err := readLiveRegistryValue(key, name, state.opts.MaxValueBytes)
			if err != nil {
				continue
			}
			if err := cb(RegistryValue{
				Root:          root,
				KeyPath:       keyPath,
				ValueName:     name,
				Type:          typ,
				Data:          data,
				Truncated:     truncated,
				IncludeBinary: state.opts.IncludeBinary,
			}); err != nil {
				return err
			}
		}
	}

	if depth >= maxDepth {
		return nil
	}
	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}
	for _, subKey := range subKeys {
		child, err := registry.OpenKey(key, subKey, registry.READ|registry.WOW64_64KEY)
		if err != nil {
			continue
		}
		childPath := subKey
		if keyPath != "" {
			childPath = keyPath + `\` + subKey
		}
		err = walkLiveRegistryKey(state, root, child, childPath, depth+1, maxDepth, cb)
		_ = child.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func readLiveRegistryValue(key registry.Key, name string, maxValueBytes int) (uint32, []byte, bool, error) {
	n, typ, err := key.GetValue(name, nil)
	if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
		return typ, nil, false, err
	}
	if n <= 0 {
		return typ, nil, false, nil
	}
	if maxValueBytes > 0 && n > maxValueBytes {
		return typ, nil, true, nil
	}
	buf := make([]byte, n)
	n, typ, err = key.GetValue(name, buf)
	if err != nil {
		return typ, nil, false, err
	}
	return typ, buf[:n], false, nil
}

func registryRootKey(root string) (registry.Key, error) {
	switch NormalizeRegistryRoot(root) {
	case "HKCU":
		return registry.CURRENT_USER, nil
	case "HKLM":
		return registry.LOCAL_MACHINE, nil
	case "HKU":
		return registry.USERS, nil
	case "HKCR":
		return registry.CLASSES_ROOT, nil
	case "HKCC":
		return registry.CURRENT_CONFIG, nil
	default:
		return 0, fmt.Errorf("unsupported registry root: %s", root)
	}
}

func (s *registryWalkState) takeKey() bool {
	if s.opts.MaxKeys > 0 && s.keys >= s.opts.MaxKeys {
		return false
	}
	s.keys++
	return true
}

func (s *registryWalkState) takeValue() bool {
	if s.opts.MaxValues > 0 && s.values >= s.opts.MaxValues {
		return false
	}
	s.values++
	return true
}

type offlineRegistry struct {
	procOpenHive  *windows.LazyProc
	procCloseHive *windows.LazyProc
	procCloseKey  *windows.LazyProc
	procOpenKey   *windows.LazyProc
	procEnumKey   *windows.LazyProc
	procEnumValue *windows.LazyProc
}

func loadOfflineRegistry() (*offlineRegistry, error) {
	if err := modoffreg.Load(); err != nil {
		return nil, fmt.Errorf("load offreg.dll: %w", err)
	}
	return &offlineRegistry{
		procOpenHive:  modoffreg.NewProc("OROpenHive"),
		procCloseHive: modoffreg.NewProc("ORCloseHive"),
		procCloseKey:  modoffreg.NewProc("ORCloseKey"),
		procOpenKey:   modoffreg.NewProc("OROpenKey"),
		procEnumKey:   modoffreg.NewProc("OREnumKey"),
		procEnumValue: modoffreg.NewProc("OREnumValue"),
	}, nil
}

func walkOfflineRegistryHive(state *registryWalkState, offreg *offlineRegistry, hive string, cb func(RegistryValue) error) error {
	hive = strings.TrimSpace(hive)
	if hive == "" {
		return nil
	}
	root, err := offreg.openHive(hive)
	if err != nil {
		return err
	}
	defer offreg.closeHive(root)
	return walkOfflineRegistryKey(state, offreg, root, hive, "", 0, state.opts.MaxDepth, cb)
}

func walkOfflineRegistryKey(state *registryWalkState, offreg *offlineRegistry, key windows.Handle, hive, keyPath string, depth, maxDepth int, cb func(RegistryValue) error) error {
	if !state.takeKey() {
		return nil
	}

	for i := uint32(0); ; i++ {
		name, typ, data, truncated, ok, err := offreg.enumValue(key, i, state.opts.MaxValueBytes)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		if !state.takeValue() {
			return nil
		}
		if err := cb(RegistryValue{
			Root:          "HIVE",
			KeyPath:       keyPath,
			ValueName:     name,
			Type:          typ,
			Data:          data,
			Hive:          hive,
			Truncated:     truncated,
			IncludeBinary: state.opts.IncludeBinary,
		}); err != nil {
			return err
		}
	}

	if depth >= maxDepth {
		return nil
	}
	for i := uint32(0); ; i++ {
		name, ok, err := offreg.enumKey(key, i)
		if err != nil {
			return err
		}
		if !ok {
			break
		}
		child, err := offreg.openKey(key, name)
		if err != nil {
			continue
		}
		childPath := name
		if keyPath != "" {
			childPath = keyPath + `\` + name
		}
		err = walkOfflineRegistryKey(state, offreg, child, hive, childPath, depth+1, maxDepth, cb)
		_ = offreg.closeKey(child)
		if err != nil {
			return err
		}
	}
	return nil
}

func (o *offlineRegistry) openHive(path string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	if err := offregErr(o.procOpenHive.Call(uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(&h)))); err != nil {
		return 0, err
	}
	return h, nil
}

func (o *offlineRegistry) closeHive(h windows.Handle) error {
	return offregErr(o.procCloseHive.Call(uintptr(h)))
}

func (o *offlineRegistry) closeKey(h windows.Handle) error {
	return offregErr(o.procCloseKey.Call(uintptr(h)))
}

func (o *offlineRegistry) openKey(root windows.Handle, path string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	if err := offregErr(o.procOpenKey.Call(uintptr(root), uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(&h)))); err != nil {
		return 0, err
	}
	return h, nil
}

func (o *offlineRegistry) enumKey(key windows.Handle, index uint32) (string, bool, error) {
	name := make([]uint16, 256)
	nameLen := uint32(len(name))
	ret, _, _ := o.procEnumKey.Call(
		uintptr(key),
		uintptr(index),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&nameLen)),
		0,
		0,
		0,
	)
	if ret == errorNoMoreItems {
		return "", false, nil
	}
	if syscall.Errno(ret) == syscall.ERROR_MORE_DATA {
		name = make([]uint16, nameLen+1)
		ret, _, _ = o.procEnumKey.Call(
			uintptr(key),
			uintptr(index),
			uintptr(unsafe.Pointer(&name[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0,
			0,
			0,
		)
	}
	if ret != 0 {
		return "", false, syscall.Errno(ret)
	}
	return syscall.UTF16ToString(name[:nameLen]), true, nil
}

func (o *offlineRegistry) enumValue(key windows.Handle, index uint32, maxValueBytes int) (string, uint32, []byte, bool, bool, error) {
	name := make([]uint16, 256)
	nameLen := uint32(len(name))
	initialDataSize := 4096
	if maxValueBytes > 0 && maxValueBytes < initialDataSize {
		initialDataSize = maxValueBytes
	}
	data := make([]byte, initialDataSize)
	dataLen := uint32(len(data))
	var valueType uint32
	ret, _, _ := o.procEnumValue.Call(
		uintptr(key),
		uintptr(index),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&nameLen)),
		uintptr(unsafe.Pointer(&valueType)),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if ret == errorNoMoreItems {
		return "", 0, nil, false, false, nil
	}
	if syscall.Errno(ret) == syscall.ERROR_MORE_DATA {
		if dataLen > uint32(maxValueBytes) && maxValueBytes > 0 {
			return syscall.UTF16ToString(name[:minInt(int(nameLen), len(name))]), valueType, nil, true, true, nil
		}
		if dataLen > uint32(len(data)) {
			data = make([]byte, dataLen)
		}
		if nameLen > uint32(len(name)) {
			name = make([]uint16, nameLen+1)
		}
		ret, _, _ = o.procEnumValue.Call(
			uintptr(key),
			uintptr(index),
			uintptr(unsafe.Pointer(&name[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			uintptr(unsafe.Pointer(&valueType)),
			uintptr(unsafe.Pointer(&data[0])),
			uintptr(unsafe.Pointer(&dataLen)),
		)
	}
	if ret != 0 {
		return "", 0, nil, false, false, syscall.Errno(ret)
	}
	return syscall.UTF16ToString(name[:nameLen]), valueType, data[:dataLen], false, true, nil
}

func offregErr(ret uintptr, _ uintptr, _ error) error {
	if ret == 0 {
		return nil
	}
	return syscall.Errno(ret)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
