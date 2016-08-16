package pe 

import (
	"regexp"
)

/* This will set a maximum length of a string to be retrieved from the file.
   It's there to prevent loading massive amounts of data from memory mapped
   files. Strings longer than 1MB should be rather rare. */
const (
	MAX_STRING_LENGTH					= 0x100000 // 2^20

	IMAGE_DOS_SIGNATURE				 	= 0x5A4D
	IMAGE_DOSZM_SIGNATURE				= 0x4D5A
	IMAGE_NE_SIGNATURE					= 0x454E
	IMAGE_LE_SIGNATURE					= 0x454C
	IMAGE_LX_SIGNATURE					= 0x584C
	IMAGE_TE_SIGNATURE					= 0x5A56 // Terse Executables have a 'VZ' signature

	IMAGE_NT_SIGNATURE					= 0x00004550
	IMAGE_NUMBEROF_DIRECTORY_ENTRIES	= 16
	IMAGE_ORDINAL_FLAG					= uint32(0x80000000)
	IMAGE_ORDINAL_FLAG64				= uint64(0x8000000000000000)
	OPTIONAL_HEADER_MAGIC_PE			= 0x10b
	OPTIONAL_HEADER_MAGIC_PE_PLUS		= 0x20b
	FILE_ALIGNMENT_HARDCODED_VALUE		= 0x200
)

var INVALID_IMP_NAME = []byte("*invalid*")

func Max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}

func Min(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}


/* Returns whether this value is a power of 2 */
func PowerOfTwo(val uint32) bool {
	ret := (val != 0) && (val & (val - 1)) == 0x0;
	return ret
}

// Check if a imported name uses the valid accepted characters expected in mangled
// function names. If the symbol's characters don't fall within this charset
// we will assume the name is invalid
//
var VALID_FUNC_NAME = regexp.MustCompile(`^[\pL\pN_\?@$\(\)]+$`)
func validFuncName(name []byte) bool {
	return VALID_FUNC_NAME.Match(name)
}

// Valid FAT32 8.3 short filename characters according to:
//  http://en.wikipedia.org/wiki/8.3_filename
// This will help decide whether DLL ASCII names are likely
// to be valid or otherwise corrupt data
//
// The filename length is not checked because the DLLs filename
// can be longer that the 8.3
var VALID_DOS_NAME = regexp.MustCompile("^[\\pL\\pN!//$%&'\\(\\)`\\-@^_\\{\\}~+,.;=\\[\\]]+$")
func validDosFilename(name []byte) bool {
	return VALID_DOS_NAME.Match(name)
}
