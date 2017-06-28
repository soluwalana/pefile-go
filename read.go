package pefile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
)

// readRVA does a binary.Read() at the given RVA by attempting to translate
// it to a file offset first
func (pe *PEFile) readRVA(iface interface{}, rva uint32) error {
	offset, err := pe.getOffsetFromRva(rva)
	if err != nil {
		return err
	}
	return pe.readOffset(iface, offset)
}

// readOffset does a binary.Read() from the file offset given
func (pe *PEFile) readOffset(iface interface{}, offset uint32) error {
	size := uint32(binary.Size(iface))
	if offset+size < offset {
		return fmt.Errorf("overflow, was -1 passed to parseHeader: %s:%x, offset 0x%x, file length: 0x%x", reflect.TypeOf(iface), size, offset, len(pe.data))
	}
	if offset+size > pe.dataLen {
		return fmt.Errorf("requested header %s:%x would read past end of the file, offset 0x%x, file length: 0x%x", reflect.TypeOf(iface), size, offset, len(pe.data))
	}

	buf := bytes.NewReader(pe.data[offset : offset+size])
	err := binary.Read(buf, binary.LittleEndian, iface)
	if err != nil {
		return err
	}
	return nil
}

// Get an ASCII string from within the data at an RVA considering
// section
func (pe *PEFile) readStringRVA(rva uint32) ([]byte, error) {
	start, length, err := pe.getDataBounds(rva)
	if err != nil {
		return nil, err
	}
	return pe.readStringOffset(start, length)
}

// Get an ASCII string from within the data.
func (pe *PEFile) readStringOffset(offset uint32, maxLen uint32) ([]byte, error) {
	if offset > pe.dataLen {
		return nil, fmt.Errorf("Attempted to read ASCII string past end of file at offset: 0x%x", offset)
	}

	for end := offset; end < pe.dataLen && end-offset < maxLen; end++ {
		if pe.data[end] == 0 {
			return pe.data[offset:end], nil
		}
	}
	return pe.data[offset:], nil
}
