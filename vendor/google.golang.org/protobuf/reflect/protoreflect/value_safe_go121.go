package protoreflect

import (
	"reflect"
)

// ifaceHeader replaces the unsafe-based ifaceHeader.
type ifaceHeader struct {
	Type reflect.Type
	Data interface{}
}

type Value struct {
	typ  reflect.Type
	data interface{}
	num  uint64
}

// valueOfString creates a Value from a string without using unsafe.
func valueOfString(v string) Value {
	return Value{
		typ:  reflect.TypeOf(v),
		data: v,
		num:  uint64(len(v)),
	}
}

// valueOfBytes creates a Value from a byte slice without using unsafe.
func valueOfBytes(v []byte) Value {
	return Value{
		typ:  reflect.TypeOf(v),
		data: append([]byte(nil), v...), // Create a copy to avoid mutation
		num:  uint64(len(v)),
	}
}

// valueOfIface creates a Value from an interface{} without using unsafe.
func valueOfIface(v interface{}) Value {
	iface := ifaceHeader{
		Type: reflect.TypeOf(v),
		Data: v,
	}
	return Value{
		typ:  reflect.TypeOf(v),
		data: iface.Data,
	}
}

// getString retrieves the string from Value without using unsafe.
func (v Value) getString() string {
	if str, ok := v.data.(string); ok {
		return str
	}
	return ""
}

// getBytes retrieves the byte slice from Value without using unsafe.
func (v Value) getBytes() []byte {
	if bytes, ok := v.data.([]byte); ok {
		return append([]byte(nil), bytes...) // Return a copy to prevent mutation
	}
	return nil
}

// getIface retrieves the interface{} from Value without using unsafe.
func (v Value) getIface() interface{} {
	return v.data
}
