package umac

import (
	"unsafe"
)

// slice hacks

func toUint32[T any](b []T) []uint32 {
	bd := (*uint32)(unsafe.Pointer(unsafe.SliceData(b)))
	return unsafe.Slice(bd, uintptr(len(b))*unsafe.Sizeof(b[0])/4)
}

func toUint64[T any](b []T) []uint64 {
	bd := (*uint64)(unsafe.Pointer(unsafe.SliceData(b)))
	return unsafe.Slice(bd, uintptr(len(b))*unsafe.Sizeof(b[0])/8)
}

func toBytes[T any](u []T) []byte {
	bd := (*byte)(unsafe.Pointer(unsafe.SliceData(u)))
	return unsafe.Slice(bd, uintptr(len(u))*unsafe.Sizeof(u[0]))
}
