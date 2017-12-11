/* This File will have the logic for parsing 32bit and 64bit Import Directories and Descriptors */

package pefile

import (
	"errors"
	"fmt"
	"log"
	"reflect"
)

/* Parse the import directory.

Given the RVA of the export directory, it will process all
its entries.

The exports will be made available as a list of ImportData
instances in the ImportDescriptors PE attribute.
*/
func (pe *PEFile) parseImportDirectory(rva, size uint32) error {

	fileOffset, err := pe.getOffsetFromRva(rva)
	if err != nil {
		return err
	}

	for fileOffset < pe.dataLen+size {

		importDesc := newImportDescriptor(fileOffset)

		if err = pe.readOffset(&importDesc.Data, fileOffset); err != nil {
			return err
		}

		if emptyStruct(importDesc.Data) {
			break
		}

		fileOffset += importDesc.Size

		importDesc.Dll, err = pe.readStringRVA(importDesc.Data.Name)
		if err != nil {
			log.Println("Error reading import name", err)
			importDesc.Dll = invalidImportName
		} else if !isValidDosFilename(importDesc.Dll) {
			importDesc.Dll = invalidImportName
		}
		log.Printf("Import descriptor name rva 0x%x: %s", importDesc.Data.Name, importDesc.Dll)

		if pe.OptionalHeader64 != nil {
			if err := pe.parseImports64(&importDesc); err != nil {
				return err
			}

			for _, imp := range importDesc.Imports64 {
				if imp.ImportByOrdinal {
					// TODO: the fixed ord lookup names were specific to a single
					// version of those files
				}
			}
		} else {
			if err := pe.parseImports(&importDesc); err != nil {
				return err
			}
			// Give pretty names to well known dll files
			for _, imp := range importDesc.Imports {
				if imp.ImportByOrdinal {
					// TODO: the fixed ord lookup names were specific to a single
					// version of those files
				}
			}
		}

		pe.ImportDescriptors = append(pe.ImportDescriptors, importDesc)
	}
	return nil
}

/*
	Parse the imported symbols.

	It will fill a list, which will be available as the dictionary
	attribute "imports". Its keys will be the DLL names and the values
	all the symbols imported from that object.
*/
func (pe *PEFile) parseImports(importDesc *ImportDescriptor) (err error) {
	var table, ilt, iat []ThunkData
	if importDesc.Data.Characteristics > 0 {
		ilt, err = pe.getImportTable(importDesc.Data.Characteristics, importDesc)
		if err != nil {
			log.Println("ILT (ImportDescriptor.Characteristics) parse error", err)
		}
	}
	if importDesc.Data.FirstThunk > 0 {
		iat, err = pe.getImportTable(importDesc.Data.FirstThunk, importDesc)
		if err != nil {
			log.Println("IAT (ImportDescriptor.FirstThunk) parse error", err)
			//return err
		}
	}

	//log.Println(ilt, iat, table)
	if len(ilt) > 0 {
		table = ilt
	} else if len(iat) > 0 {
		table = iat
	} else {
		return errors.New("Invalid Import Table information. Both ILT and IAT appear to be broken.")
	}

	impOffset := uint32(0x4)
	addressMask := uint32(0x7fffffff)
	ordinalFlag := IMAGE_ORDINAL_FLAG

	numInvalid := uint32(0)

	for idx, thunk := range table {
		var imp ImportData
		imp.StructTable = thunk
		imp.OrdinalOffset = thunk.FileOffset

		if thunk.Data.AddressOfData > 0 {

			// If imported by ordinal, we will append the ordinal numberx
			if table[idx].Data.AddressOfData&ordinalFlag > 0 {
				imp.ImportByOrdinal = true
				imp.Ordinal = table[idx].Data.AddressOfData & uint32(0xffff)
			} else {
				imp.ImportByOrdinal = false
				imp.HintNameTableRva = table[idx].Data.AddressOfData & addressMask

				if imp.HintNameTableRva > 0 {
					if err := pe.readRVA(&imp.Hint, imp.HintNameTableRva); err != nil {
						return err
					}
				}

				imp.Name, err = pe.readStringRVA(table[idx].Data.AddressOfData + 2)
				if err != nil {
					log.Println("Error reading import name", err)
					imp.Name = invalidImportName
				} else if !isValidFuncName(imp.Name) {
					imp.Name = invalidImportName
				}
				imp.NameOffset, err = pe.getOffsetFromRva(table[idx].Data.AddressOfData + 2)
				if err != nil {
					return err
				}
			}
			imp.ThunkOffset = table[idx].FileOffset
			imp.ThunkRva = pe.getRvaFromOffset(imp.ThunkOffset)
		}

		imp.Address = importDesc.Data.FirstThunk + pe.OptionalHeader.Data.ImageBase + (uint32(idx) * impOffset)

		if idx < len(iat) && idx < len(ilt) && ilt[idx].Data.AddressOfData != iat[idx].Data.AddressOfData {
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
		if reflect.DeepEqual(imp.Name, invalidImportName) {
			if numInvalid > 1000 && numInvalid == uint32(idx) {
				return errors.New("Too many invalid names, aborting parsing")
			}
			numInvalid++
			continue
		}

		if imp.Ordinal > 0 || hasName {
			importDesc.Imports = append(importDesc.Imports, imp)
		}
	}

	return nil
}

const (
	maxAddressSpread     = uint32(134217728) // 128 MB
	maxRepeatedAddresses = uint32(16)
)

func (pe *PEFile) getImportTable(startRVA uint32, importDesc *ImportDescriptor) ([]ThunkData, error) {
	// Setup variables
	thunkTable := make(map[uint32]ThunkData)
	var retVal []ThunkData

	ordinalFlag := IMAGE_ORDINAL_FLAG
	repeatedAddresses := uint32(0)

	minAddressOfData := ^uint32(0)
	maxAddressOfData := uint32(0)

	maxLen := pe.dataLen - importDesc.FileOffset
	if startRVA > importDesc.Data.Characteristics || startRVA > importDesc.Data.FirstThunk {
		maxLen = max(startRVA-importDesc.Data.Characteristics, startRVA-importDesc.Data.FirstThunk)
	}
	lastAddr := startRVA + maxLen

	// logic start			break

	for rva := startRVA; rva < lastAddr; {
		if rva >= lastAddr {
			log.Println("Error parsing the import table. Entries go beyond bounds.")
			break
		}
		// if we see too many times the same entry we assume it could be
		// a table containing bogus data (with malicious intent or otherwise)
		if repeatedAddresses >= maxRepeatedAddresses {
			return nil, errors.New("bogus data found in imports")
		}

		// if the addresses point somewhere but the difference between the highest
		// and lowest address is larger than MAX_ADDRESS_SPREAD we assume a bogus
		// table as the addresses should be contained within a module
		if maxAddressOfData-minAddressOfData > maxAddressSpread {
			return nil, fmt.Errorf("data addresses too spread out, min 0x%x max 0x%x", minAddressOfData, maxAddressOfData)
		}

		thunkOffset, err := pe.getOffsetFromRva(rva)
		if err != nil {
			return nil, err
		}
		thunk := newThunkData(thunkOffset)
		if err := pe.readOffset(&thunk.Data, thunk.FileOffset); err != nil {
			msg := fmt.Sprintf("Error Parsing the import table.\nInvalid data at RVA: 0x%x", rva)
			log.Println(msg)
			return nil, errors.New(msg)
		}

		if emptyStruct(thunk.Data) {
			break
		}

		// Check if the AddressOfData lies within the range of RVAs that it's
		// being scanned, abort if that is the case, as it is very unlikely
		// to be legitimate data.
		// Seen in PE with SHA256:
		// 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
		if thunk.Data.AddressOfData >= startRVA && thunk.Data.AddressOfData <= rva {
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
					return nil, errors.New(msg)
				}
				// and if it looks like it should be an RVA
			} else {
				// keep track of the RVAs seen and store them to study their
				// properties. When certain non-standard features are detected
				// the parsing will be aborted
				if _, ok := thunkTable[rva]; ok {
					repeatedAddresses++
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

func (pe *PEFile) parseImports64(importDesc *ImportDescriptor) (err error) {
	// Todo not implemented yet
	return nil
}

func (pe *PEFile) getImportTable64(rva uint64) []ThunkData64 {
	// todo not implemeted yet
	return []ThunkData64{}
}
