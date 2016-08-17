/* This File will have the logic for parsing 32bit and 64bit Import Directories and Descriptors */

package pe

import (
	"errors"
	"fmt"
	"github.com/dgrif/pefile-go/lib"
	"log"
	"reflect"
)

/* Parse the import directory.

Given the RVA of the export directory, it will process all
its entries.

The exports will be made available as a list of ImportData
instances in the ImportDescriptors PE attribute.
*/
func (self *PEFile) parseImportDirectory(rva, size uint32) (err error) {
	self.ImportDescriptors = make([]*lib.ImportDescriptor, 0)

	for {

		fileOffset := self.getOffsetFromRva(rva)
		importDesc := lib.NewImportDescriptor(fileOffset)

		if (importDesc.Size + rva) > self.dataLen {
			return errors.New("Not enough space for importDesc")
		}

		if err = self.parseHeader(&importDesc.Data, fileOffset, importDesc.Size); err != nil {
			return err
		}

		log.Printf("0x%x == %s", importDesc.Data.Name, self.getStringAtRva(importDesc.Data.Name))
		if lib.EmptyStruct(importDesc.Data) {
			break
		}

		rva += importDesc.Size

		importDesc.Dll = self.getStringAtRva(importDesc.Data.Name)
		if !validDosFilename(importDesc.Dll) {
			importDesc.Dll = INVALID_IMP_NAME
		}

		if self.OptionalHeader64 != nil {
			if err := self.parseImports64(importDesc); err != nil {
				return err
			}
			// Give pretty names to well known dll files
			for _, imp := range importDesc.Imports64 {
				if imp.ImportByOrdinal {
					if funcname := OrdLookup(string(importDesc.Dll), imp.Ordinal, false); len(funcname) > 0 {
						imp.Name = []byte(funcname)
					}
				}
			}
		} else {
			if err := self.parseImports(importDesc); err != nil {
				return err
			}
			// Give pretty names to well known dll files
			for _, imp := range importDesc.Imports {
				if imp.ImportByOrdinal {
					if funcname := OrdLookup(string(importDesc.Dll), uint64(imp.Ordinal), false); len(funcname) > 0 {
						imp.Name = []byte(funcname)
					}
				}
			}
		}

		self.ImportDescriptors = append(self.ImportDescriptors, importDesc)
	}
	return nil
}

/*
	Parse the imported symbols.

	It will fill a list, which will be available as the dictionary
	attribute "imports". Its keys will be the DLL names and the values
	all the symbols imported from that object.
*/
func (self *PEFile) parseImports(importDesc *lib.ImportDescriptor) (err error) {
	var table []*lib.ThunkData
	ilt, err := self.getImportTable(importDesc.Data.Characteristics, importDesc)
	if err != nil {
		return err
	}
	iat, err := self.getImportTable(importDesc.Data.FirstThunk, importDesc)
	if err != nil {
		return err
	}

	if len(iat) == 0 && len(ilt) == 0 {
		return errors.New("Invalid Import Table information. Both ILT and IAT appear to be broken.")
	}

	impOffset := uint32(0x4)
	addressMask := uint32(0x7fffffff)
	ordinalFlag := IMAGE_ORDINAL_FLAG

	numInvalid := uint32(0)

	if len(ilt) > 0 {
		table = ilt
	} else {
		table = iat
	}

	for idx := uint32(0); idx < uint32(len(table)); idx++ {
		imp := new(lib.ImportData)
		imp.StructTable = table[idx]
		imp.OrdinalOffset = table[idx].FileOffset

		if table[idx].Data.AddressOfData > 0 {

			// If imported by ordinal, we will append the ordinal numberx
			if table[idx].Data.AddressOfData&ordinalFlag > 0 {
				imp.ImportByOrdinal = true
				imp.Ordinal = table[idx].Data.AddressOfData & uint32(0xffff)
			} else {
				imp.ImportByOrdinal = false
				imp.HintNameTableRva = table[idx].Data.AddressOfData & addressMask

				if err := self.parseHeader(&imp.Hint, imp.HintNameTableRva, 2); err != nil {
					return err
				}

				imp.Name = self.getStringAtRva(table[idx].Data.AddressOfData + 2)

				if !validFuncName(imp.Name) {
					imp.Name = INVALID_IMP_NAME
				}
				imp.NameOffset = self.getOffsetFromRva(table[idx].Data.AddressOfData + 2)
			}
			imp.ThunkOffset = table[idx].FileOffset
			imp.ThunkRva = self.getRvaFromOffset(imp.ThunkOffset)
		}

		imp.Address = importDesc.Data.FirstThunk + self.OptionalHeader.Data.ImageBase + (idx * impOffset)

		if len(iat) > 0 && len(ilt) > 0 && ilt[idx].Data.AddressOfData != iat[idx].Data.AddressOfData {
			imp.Bound = iat[idx].Data.AddressOfData
			imp.StructIat = iat[idx]
		}

		hasName := len(imp.Name) > 0

		// The file with hashe:
		// SHA256: 3d22f8b001423cb460811ab4f4789f277b35838d45c62ec0454c877e7c82c7f5
		// has an invalid table built in a way that it's parseable but contains
		// invalid entries
		if imp.Ordinal == 0 && !hasName {
			return errors.New("Must have either an ordinal or a name in an import")
		}
		// Some PEs appear to interleave valid and invalid imports. Instead of
		// aborting the parsing altogether we will simply skip the invalid entries.
		// Although if we see 1000 invalid entries and no legit ones, we abort.
		if reflect.DeepEqual(imp.Name, INVALID_IMP_NAME) {
			if numInvalid > 1000 && numInvalid == idx {
				return errors.New("Too many invalid names, aborting parsing")
			}
			numInvalid += 1
			continue
		}

		if imp.Ordinal > 0 || hasName {
			importDesc.Imports = append(importDesc.Imports, imp)
		}
	}

	return nil
}

func (self *PEFile) getImportTable(rva uint32, importDesc *lib.ImportDescriptor) ([]*lib.ThunkData, error) {
	// Setup variables
	thunkTable := make(map[uint32]*lib.ThunkData)
	retVal := make([]*lib.ThunkData, 0)

	MAX_ADDRESS_SPREAD := uint32(134217728) // 128 MB
	MAX_REPEATED_ADDRESSES := uint32(16)

	ordinalFlag := IMAGE_ORDINAL_FLAG
	repeatedAddresses := uint32(0)
	startRva := rva

	minAddressOfData := ^uint32(0)
	maxAddressOfData := uint32(0)

	maxLen := self.dataLen - importDesc.FileOffset
	if rva > importDesc.Data.Characteristics || rva > importDesc.Data.FirstThunk {
		maxLen = Max(rva-importDesc.Data.Characteristics, rva-importDesc.Data.FirstThunk)
	}
	lastAddr := rva + maxLen

	// logic start
	for {
		if rva >= lastAddr {
			log.Println("Error parsing the import table. Entries go beyond bounds.")
			break
		}
		// if we see too many times the same entry we assume it could be
		// a table containing bogus data (with malicious intent or otherwise)
		if repeatedAddresses >= MAX_REPEATED_ADDRESSES {
			return []*lib.ThunkData{}, errors.New("bogus data found in imports")
		}

		// if the addresses point somewhere but the difference between the highest
		// and lowest address is larger than MAX_ADDRESS_SPREAD we assume a bogus
		// table as the addresses should be contained within a module
		if maxAddressOfData-minAddressOfData > MAX_ADDRESS_SPREAD {
			return []*lib.ThunkData{}, errors.New("data addresses too spread out")
		}

		thunk := lib.NewThunkData(self.getOffsetFromRva(rva))
		if err := self.parseHeader(&thunk.Data, thunk.FileOffset, thunk.Size); err != nil {
			msg := fmt.Sprintf("Error Parsing the import table.\nInvalid data at RVA: 0x%x", rva)
			log.Println(msg)
			return []*lib.ThunkData{}, errors.New(msg)
		}

		if lib.EmptyStruct(thunk.Data) {
			break
		}

		// Check if the AddressOfData lies within the range of RVAs that it's
		// being scanned, abort if that is the case, as it is very unlikely
		// to be legitimate data.
		// Seen in PE with SHA256:
		// 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
		if thunk.Data.AddressOfData >= startRva && thunk.Data.AddressOfData <= rva {
			log.Printf("Error parsing the import table. "+
				"AddressOfData overlaps with THUNK_DATA for THUNK at:\n  "+
				"RVA 0x%x", rva)
			break
		}

		if thunk.Data.AddressOfData > 0 {
			// If the entry looks like could be an ordinal...
			if thunk.Data.AddressOfData&ordinalFlag > 0 {
				// but its value is beyond 2^16, we will assume it's a
				// corrupted and ignore it altogether
				if thunk.Data.AddressOfData&uint32(0x7fffffff) > uint32(0xffff) {
					msg := fmt.Sprintf("Corruption detected in thunk data at 0x%x", rva)
					log.Printf(msg)
					return []*lib.ThunkData{}, errors.New(msg)
				}
				// and if it looks like it should be an RVA
			} else {
				// keep track of the RVAs seen and store them to study their
				// properties. When certain non-standard features are detected
				// the parsing will be aborted
				if _, ok := thunkTable[rva]; ok {
					repeatedAddresses += 1
				}
				if thunk.Data.AddressOfData > maxAddressOfData {
					maxAddressOfData = thunk.Data.AddressOfData
				}
				if thunk.Data.AddressOfData < minAddressOfData {
					minAddressOfData = thunk.Data.AddressOfData
				}
			}
		}

		thunkTable[rva] = thunk
		retVal = append(retVal, thunk)
		rva += thunk.Size
	}
	return retVal, nil
}

func (self *PEFile) parseImports64(importDesc *lib.ImportDescriptor) (err error) {
	// Todo not implemented yet
	return nil
}

func (self *PEFile) getImportTable64(rva uint64) []*lib.ThunkData64 {
	// todo not implemeted yet
	return []*lib.ThunkData64{}
}
