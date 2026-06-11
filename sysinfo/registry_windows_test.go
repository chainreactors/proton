//go:build windows

package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type registryWalkStats struct {
	Keys      map[string]struct{}
	Values    int
	DataBytes int
}

type offlineRegistryWriter struct {
	procCreateHive *windows.LazyProc
	procCloseHive  *windows.LazyProc
	procCloseKey   *windows.LazyProc
	procCreateKey  *windows.LazyProc
	procSetValue   *windows.LazyProc
	procSaveHive   *windows.LazyProc
}

func TestWindowsRegistryLiveSmoke(t *testing.T) {
	marker := fmt.Sprintf("PROTON_SYSINFO_REGISTRY_%d", time.Now().UnixNano())
	path := fmt.Sprintf(`Software\Chainreactors\ProtonRegistryTest_%d`, time.Now().UnixNano())

	key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if err := key.SetStringValue("Marker", marker); err != nil {
		_ = key.Close()
		t.Fatalf("SetStringValue: %v", err)
	}
	if err := key.Close(); err != nil {
		t.Fatalf("Close registry key: %v", err)
	}
	defer registry.DeleteKey(registry.CURRENT_USER, path)

	found := false
	err = WalkRegistry(RegistryWalkOptions{
		Targets: []RegistryTarget{{Root: "HKCU", Path: path, MaxDepth: 1}},
	}, func(v RegistryValue) error {
		if strings.Contains(string(v.Record()), marker) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkRegistry live: %v", err)
	}
	if !found {
		t.Fatal("live registry marker not found")
	}
}

func TestWindowsOfflineRegistryLibrarySmoke(t *testing.T) {
	writer, err := loadOfflineRegistryWriter()
	if err != nil {
		t.Skipf("offreg.dll unavailable: %v", err)
	}

	marker := fmt.Sprintf("PROTON_SYSINFO_OFFREG_%d", time.Now().UnixNano())
	hivePath := filepath.Join(t.TempDir(), "proton-offreg-smoke.hiv")

	start := time.Now()
	root, err := writer.createHiveRoot()
	if err != nil {
		t.Fatalf("ORCreateHive: %v", err)
	}
	key, err := writer.createKeyPath(root, `Software\Chainreactors\Proton`)
	if err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORCreateKey: %v", err)
	}
	if err := writer.setStringValue(key, "Marker", marker); err != nil {
		_ = writer.closeKey(key)
		_ = writer.closeHive(root)
		t.Fatalf("ORSetValue: %v", err)
	}
	if err := writer.closeKey(key); err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORCloseKey: %v", err)
	}
	if err := writer.saveHive(root, hivePath); err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORSaveHive: %v", err)
	}
	if err := writer.closeHive(root); err != nil {
		t.Fatalf("ORCloseHive: %v", err)
	}
	createSaveDuration := time.Since(start)

	openWalkStart := time.Now()
	var stats registryWalkStats
	found := false
	err = WalkRegistry(RegistryWalkOptions{
		Hives: []string{hivePath},
	}, func(v RegistryValue) error {
		stats.add(v)
		if strings.Contains(string(v.Record()), marker) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkRegistry offline hive: %v", err)
	}
	openWalkDuration := time.Since(openWalkStart)
	if !found {
		t.Fatal("marker value not found in offline hive")
	}
	if len(stats.Keys) == 0 || stats.Values == 0 {
		t.Fatalf("unexpected offline stats: %+v", stats)
	}

	t.Logf("offline_hive path_size=%d keys=%d values=%d data_bytes=%d create_save=%s open_walk=%s",
		fileSize(hivePath), len(stats.Keys), stats.Values, stats.DataBytes, createSaveDuration, openWalkDuration)
}

func TestWindowsOfflineRegistryMaxValuesDoesNotCountEmptyKeys(t *testing.T) {
	writer, err := loadOfflineRegistryWriter()
	if err != nil {
		t.Skipf("offreg.dll unavailable: %v", err)
	}

	marker := fmt.Sprintf("PROTON_SYSINFO_OFFREG_LIMIT_%d", time.Now().UnixNano())
	hivePath := filepath.Join(t.TempDir(), "proton-offreg-limit.hiv")

	root, err := writer.createHiveRoot()
	if err != nil {
		t.Fatalf("ORCreateHive: %v", err)
	}
	key, err := writer.createKeyPath(root, `Software\Chainreactors\ProtonLimit`)
	if err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORCreateKey: %v", err)
	}
	if err := writer.setStringValue(key, "Marker", marker); err != nil {
		_ = writer.closeKey(key)
		_ = writer.closeHive(root)
		t.Fatalf("ORSetValue: %v", err)
	}
	if err := writer.closeKey(key); err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORCloseKey: %v", err)
	}
	if err := writer.saveHive(root, hivePath); err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORSaveHive: %v", err)
	}
	if err := writer.closeHive(root); err != nil {
		t.Fatalf("ORCloseHive: %v", err)
	}

	found := false
	err = WalkRegistry(RegistryWalkOptions{
		Hives:     []string{hivePath},
		MaxDepth:  5,
		MaxValues: 1,
	}, func(v RegistryValue) error {
		if strings.Contains(string(v.Record()), marker) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkRegistry offline hive: %v", err)
	}
	if !found {
		t.Fatal("marker value not found with MaxValues=1")
	}
}

func TestWindowsOfflineRegistryLibrarySyntheticPerformance(t *testing.T) {
	writer, err := loadOfflineRegistryWriter()
	if err != nil {
		t.Skipf("offreg.dll unavailable: %v", err)
	}

	const keyCount = 1000
	hivePath := filepath.Join(t.TempDir(), "proton-offreg-synthetic.hiv")
	start := time.Now()
	root, err := writer.createHiveRoot()
	if err != nil {
		t.Fatalf("ORCreateHive: %v", err)
	}
	benchRoot, err := writer.createKeyPath(root, `Software\Chainreactors\ProtonBench`)
	if err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORCreateKey bench root: %v", err)
	}
	for i := 0; i < keyCount; i++ {
		child, err := writer.createKey(benchRoot, fmt.Sprintf("K%04d", i))
		if err != nil {
			_ = writer.closeKey(benchRoot)
			_ = writer.closeHive(root)
			t.Fatalf("ORCreateKey synthetic %d: %v", i, err)
		}
		if err := writer.setStringValue(child, "Value", fmt.Sprintf("synthetic-%04d", i)); err != nil {
			_ = writer.closeKey(child)
			_ = writer.closeKey(benchRoot)
			_ = writer.closeHive(root)
			t.Fatalf("ORSetValue synthetic %d: %v", i, err)
		}
		if err := writer.closeKey(child); err != nil {
			_ = writer.closeKey(benchRoot)
			_ = writer.closeHive(root)
			t.Fatalf("ORCloseKey synthetic %d: %v", i, err)
		}
	}
	if err := writer.closeKey(benchRoot); err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORCloseKey bench root: %v", err)
	}
	if err := writer.saveHive(root, hivePath); err != nil {
		_ = writer.closeHive(root)
		t.Fatalf("ORSaveHive synthetic: %v", err)
	}
	if err := writer.closeHive(root); err != nil {
		t.Fatalf("ORCloseHive synthetic: %v", err)
	}
	createSaveDuration := time.Since(start)

	openWalkStart := time.Now()
	var stats registryWalkStats
	err = WalkRegistry(RegistryWalkOptions{
		Hives:    []string{hivePath},
		MaxDepth: 5,
		MaxKeys:  keyCount + 16,
	}, func(v RegistryValue) error {
		stats.add(v)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkRegistry synthetic hive: %v", err)
	}
	openWalkDuration := time.Since(openWalkStart)
	if len(stats.Keys) < keyCount || stats.Values < keyCount {
		t.Fatalf("unexpected synthetic stats: %+v", stats)
	}
	t.Logf("offline_hive_synthetic keys=%d values=%d data_bytes=%d path_size=%d create_save=%s open_walk=%s",
		len(stats.Keys), stats.Values, stats.DataBytes, fileSize(hivePath), createSaveDuration, openWalkDuration)
}

func TestWindowsLiveRegistryImportantPathsPerformance(t *testing.T) {
	var total registryWalkStats
	start := time.Now()
	for _, target := range DefaultRegistryTargets() {
		pathStart := time.Now()
		var stats registryWalkStats
		err := WalkRegistry(RegistryWalkOptions{
			Targets:       []RegistryTarget{target},
			MaxKeys:       3000,
			MaxValues:     20000,
			MaxValueBytes: DefaultRegistryMaxValueBytes,
		}, func(v RegistryValue) error {
			stats.add(v)
			return nil
		})
		elapsed := time.Since(pathStart)
		if err != nil {
			t.Fatalf("WalkRegistry %s\\%s: %v", target.Root, target.Path, err)
		}
		total.merge(stats)
		t.Logf("live_registry path=%s\\%s depth=%d keys=%d values=%d data_bytes=%d elapsed=%s",
			target.Root, target.Path, target.MaxDepth, len(stats.Keys), stats.Values, stats.DataBytes, elapsed)
	}
	t.Logf("live_registry_total keys=%d values=%d data_bytes=%d elapsed=%s",
		len(total.Keys), total.Values, total.DataBytes, time.Since(start))
}

func (s *registryWalkStats) add(v RegistryValue) {
	if s.Keys == nil {
		s.Keys = make(map[string]struct{})
	}
	key := v.Root + `\` + v.KeyPath
	if v.Hive != "" {
		key = v.Hive + `:` + v.KeyPath
	}
	s.Keys[key] = struct{}{}
	s.Values++
	s.DataBytes += len(v.Data)
}

func (s *registryWalkStats) merge(other registryWalkStats) {
	if s.Keys == nil {
		s.Keys = make(map[string]struct{})
	}
	for key := range other.Keys {
		s.Keys[key] = struct{}{}
	}
	s.Values += other.Values
	s.DataBytes += other.DataBytes
}

func loadOfflineRegistryWriter() (*offlineRegistryWriter, error) {
	if err := modoffreg.Load(); err != nil {
		return nil, err
	}
	return &offlineRegistryWriter{
		procCreateHive: modoffreg.NewProc("ORCreateHive"),
		procCloseHive:  modoffreg.NewProc("ORCloseHive"),
		procCloseKey:   modoffreg.NewProc("ORCloseKey"),
		procCreateKey:  modoffreg.NewProc("ORCreateKey"),
		procSetValue:   modoffreg.NewProc("ORSetValue"),
		procSaveHive:   modoffreg.NewProc("ORSaveHive"),
	}, nil
}

func (o *offlineRegistryWriter) createHiveRoot() (windows.Handle, error) {
	var h windows.Handle
	if err := offregErr(o.procCreateHive.Call(uintptr(unsafe.Pointer(&h)))); err != nil {
		return 0, err
	}
	return h, nil
}

func (o *offlineRegistryWriter) closeHive(h windows.Handle) error {
	return offregErr(o.procCloseHive.Call(uintptr(h)))
}

func (o *offlineRegistryWriter) closeKey(h windows.Handle) error {
	return offregErr(o.procCloseKey.Call(uintptr(h)))
}

func (o *offlineRegistryWriter) createKey(root windows.Handle, path string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	var disposition uint32
	if err := offregErr(o.procCreateKey.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(ptr)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(&disposition)),
	)); err != nil {
		return 0, err
	}
	return h, nil
}

func (o *offlineRegistryWriter) createKeyPath(root windows.Handle, path string) (windows.Handle, error) {
	parts := strings.Split(path, `\`)
	parent := root
	var opened []windows.Handle
	for _, part := range parts {
		if part == "" {
			continue
		}
		child, err := o.createKey(parent, part)
		if err != nil {
			for i := len(opened) - 1; i >= 0; i-- {
				_ = o.closeKey(opened[i])
			}
			return 0, err
		}
		opened = append(opened, child)
		parent = child
	}
	for i := 0; i < len(opened)-1; i++ {
		_ = o.closeKey(opened[i])
	}
	if len(opened) == 0 {
		return root, nil
	}
	return opened[len(opened)-1], nil
}

func (o *offlineRegistryWriter) setStringValue(key windows.Handle, name, value string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	data, err := utf16ValueBytes(value)
	if err != nil {
		return err
	}
	return offregErr(o.procSetValue.Call(
		uintptr(key),
		uintptr(unsafe.Pointer(namePtr)),
		RegistryTypeString,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
	))
}

func (o *offlineRegistryWriter) saveHive(root windows.Handle, path string) error {
	_ = os.Remove(path)
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return offregErr(o.procSaveHive.Call(uintptr(root), uintptr(unsafe.Pointer(ptr)), 10, 0))
}

func utf16ValueBytes(value string) ([]byte, error) {
	u16, err := windows.UTF16FromString(value)
	if err != nil {
		return nil, err
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(&u16[0])), len(u16)*2)
	copied := make([]byte, len(data))
	copy(copied, data)
	return copied, nil
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}
