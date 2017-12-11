package pefile

import (
	"errors"
	"fmt"
	//"reflect"
	"log"
)

/* Parse the export directory.

Given the RVA of the export directory, it will process all
its entries.

The exports will be made available as a list of ExportData
instances in the ExportDescriptors PE attribute.
*/
func (pe *PEFile) parseExportDirectory(rva, size uint32) (err error) {
	exportDirOffset, err := pe.getOffsetFromRva(rva)
	if err != nil {
		return err
	}

	exportDir := newExportDirectory(exportDirOffset)
	start, _, err := pe.getDataBounds(rva)
	if err = pe.readOffset(&exportDir.Data, start); err != nil {
		return err
	}
	pe.ExportDirectory = exportDir

	lenAddrOfFuncs := exportDir.Data.NumberOfFunctions * 4
	startAddrOfFuncs, length, err := pe.getDataBounds(exportDir.Data.AddressOfFunctions)

	if err != nil {
		return err
	}
	if length < lenAddrOfFuncs {
		log.Printf("AddressOfFunctions would extend past the section end")
		return fmt.Errorf("AddressOfFunctions would extend past the section end")
	}

	exportDir.Exports = make([]ExportData, exportDir.Data.NumberOfFunctions)

	for ordinalIndex := range exportDir.Exports {
		e := &exportDir.Exports[ordinalIndex]
		e.Ordinal = uint16(uint32(ordinalIndex) + exportDir.Data.Base)

		// Address
		e.AddressOffset = startAddrOfFuncs + (uint32(ordinalIndex) * 4)
		if err = pe.readOffset(&e.Address, e.AddressOffset); err != nil {
			// This is v bad since it should be readable based on length check
			return err
		}
		if e.Address == 0 {
			continue
		}

		// Forwarder if applicable
		if e.Address >= rva && e.Address < rva+size {
			e.ForwarderOffset, err = pe.getOffsetFromRva(e.Address)
			if err != nil {
				return err
			}
			e.Forwarder, err = pe.readStringRVA(e.Address)
			if err != nil {
				log.Printf("%s", err.Error())
			}
		}
	}

	startAddrOfNames, lengthOfNames, err := pe.getDataBounds(exportDir.Data.AddressOfNames)
	if err != nil {
		return err
	}
	startAddrOfNameOrdinals, lengthOfNameOrdinals, err := pe.getDataBounds(exportDir.Data.AddressOfNameOrdinals)
	if err != nil {
		return err
	}

	expectedLengthOfNameOrdinals := exportDir.Data.NumberOfNames * 2
	expectedLengthOfNames := exportDir.Data.NumberOfNames * 4
	if lengthOfNames < expectedLengthOfNames || lengthOfNameOrdinals < expectedLengthOfNameOrdinals {
		return errors.New("AddressOfNames or AddressOfNameOrdinals extend past section bounds")
	}

	for nameIndex := uint32(0); nameIndex < exportDir.Data.NumberOfNames; nameIndex++ {
		nameOffset := startAddrOfNames + (nameIndex * 4)
		ordOffset := startAddrOfNameOrdinals + (nameIndex * 2)

		var nameAddr uint32
		if err = pe.readOffset(&nameAddr, nameOffset); err != nil {
			return err
		}
		name, err := pe.readStringRVA(nameAddr)
		if err != nil {
			log.Println("Error reading symbol name", err)
			break
		}

		// ordinalIndex is the literal index into the ordinal array, it does
		// not include Base
		var ordinalIndex uint16
		if err = pe.readOffset(&ordinalIndex, ordOffset); err != nil {
			return err
		}

		if uint32(ordinalIndex) > exportDir.Data.NumberOfFunctions {
			ordinal := ordinalIndex + uint16(exportDir.Data.Base)
			log.Println("Invalid ordinal index/ordinal", ordinalIndex, "/", ordinal, " for ", name)
			e := ExportData{
				NameOffset:    nameOffset,
				Name:          name,
				OrdinalOffset: ordOffset,
				Ordinal:       ordinalIndex,
			}
			exportDir.Exports = append(exportDir.Exports, e)
			continue
		}

		if len(exportDir.Exports[ordinalIndex].Name) == 0 {
			exportDir.Exports[ordinalIndex].NameOffset = nameOffset
			exportDir.Exports[ordinalIndex].Name = name
			exportDir.Exports[ordinalIndex].OrdinalOffset = ordOffset
		} else {
			var e = exportDir.Exports[ordinalIndex]
			e.NameOffset = nameOffset
			e.Name = name
			e.OrdinalOffset = ordOffset
			exportDir.Exports = append(exportDir.Exports, e)
		}

	}

	return nil
}
