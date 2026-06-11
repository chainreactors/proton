//go:build darwin && cgo

package sysinfo

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdlib.h>

static kern_return_t read_memory(mach_port_t task, mach_vm_address_t addr,
	mach_vm_size_t size, void *buf, mach_vm_size_t *out_size) {
	vm_offset_t data;
	mach_msg_type_number_t count;
	kern_return_t kr = mach_vm_read(task, addr, size, &data, &count);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	if (count > size) count = size;
	memcpy(buf, (void*)data, count);
	*out_size = count;
	mach_vm_deallocate(mach_task_self(), data, count);
	return KERN_SUCCESS;
}

static kern_return_t get_region(mach_port_t task, mach_vm_address_t *addr,
	mach_vm_size_t *size, vm_region_basic_info_data_64_t *info) {
	mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t object_name;
	return mach_vm_region(task, addr, size, VM_REGION_BASIC_INFO_64,
		(vm_region_info_t)info, &count, &object_name);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type darwinMemReader struct {
	task C.mach_port_t
	pid  int
}

func NewMemoryReader(pid int) (MemoryReader, error) {
	var task C.mach_port_t
	kr := C.task_for_pid(C.mach_task_self(), C.int(pid), &task)
	if kr != C.KERN_SUCCESS {
		return nil, fmt.Errorf("task_for_pid(%d) failed: kern_return=%d (requires root or debugger entitlement)", pid, kr)
	}
	return &darwinMemReader{task: task, pid: pid}, nil
}

func (r *darwinMemReader) Regions() ([]MemoryRegion, error) {
	var regions []MemoryRegion
	var addr C.mach_vm_address_t

	for {
		var size C.mach_vm_size_t
		var info C.vm_region_basic_info_data_64_t
		kr := C.get_region(r.task, &addr, &size, &info)
		if kr != C.KERN_SUCCESS {
			break
		}

		perms := machProtToPerms(int(info.protection))
		regions = append(regions, MemoryRegion{
			BaseAddr: uint64(addr),
			Size:     uint64(size),
			Perms:    perms,
		})

		addr += C.mach_vm_address_t(size)
		if uint64(addr) < uint64(addr)-uint64(size) {
			break
		}
	}
	return regions, nil
}

func machProtToPerms(prot int) string {
	r := "-"
	w := "-"
	x := "-"
	if prot&1 != 0 {
		r = "r"
	}
	if prot&2 != 0 {
		w = "w"
	}
	if prot&4 != 0 {
		x = "x"
	}
	return r + w + x
}

func (r *darwinMemReader) ReadAt(buf []byte, addr uint64) (int, error) {
	var outSize C.mach_vm_size_t
	kr := C.read_memory(r.task, C.mach_vm_address_t(addr),
		C.mach_vm_size_t(len(buf)), unsafe.Pointer(&buf[0]), &outSize)
	if kr != C.KERN_SUCCESS {
		return 0, fmt.Errorf("mach_vm_read at 0x%x failed: kern_return=%d", addr, kr)
	}
	return int(outSize), nil
}

func (r *darwinMemReader) Close() error {
	C.mach_port_deallocate(C.mach_task_self(), r.task)
	return nil
}
