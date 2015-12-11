package pe

import (
	"errors"
	"../lib"
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
func (self *PEFile) parseExportDirectory(rva, size uint32) (err error) {
	
	exportDir := lib.NewExportDirectory(self.getOffsetFromRva(rva))
	start, _ := self.getDataBounds(rva, 0)
	if err = self.parseHeader(&exportDir.Data, start, exportDir.Size); err != nil {
		return err
	}
	self.ExportDirectory = exportDir

	log.Println(exportDir)
	startAddrOfNames, _ := self.getDataBounds(exportDir.Data.AddressOfNames, 0)
	startAddrOfOrdinals, _ := self.getDataBounds(exportDir.Data.AddressOfNameOrdinals, 0)
	startAddrOfFuncs, _ := self.getDataBounds(exportDir.Data.AddressOfFunctions, 0)
	
	
	errMsg := "RVA %s in the export directory points to an invalid address: %x"
	//maxErrors := 10

	section := self.getSectionByRva(exportDir.Data.AddressOfNames)
	if section == nil {
		log.Printf(errMsg, "AddressOfNames", exportDir.Data.AddressOfNames)
		return errors.New(fmt.Sprintf(errMsg, "AddressOfNames", exportDir.Data.AddressOfNames))

	}
	
	safetyBoundary := section.Data.VirtualAddress + section.Data.SizeOfRawData - exportDir.Data.AddressOfNames
	numNames := Min(safetyBoundary / 4, exportDir.Data.NumberOfNames)

	// A hash set for tracking seen ordinals
	ordMap := make(map[uint16]bool)

	fmt.Printf("Safety boundary %x, num names %d\n", safetyBoundary, numNames)
	for i := uint32(0); i < numNames; i ++ {
		sym := new(lib.ExportData)

		// Name and name offset
		var symNameAddr uint32
		sym.NameOffset = startAddrOfNames + (i * 4)
		if err = self.parseHeader(&symNameAddr, sym.NameOffset, 4); err != nil {
			return err
		}
		sym.Name = self.getStringAtRva(symNameAddr)
		log.Printf("%s\n", sym.Name)
		if !validFuncName(sym.Name) {
			break
		}
		sym.NameOffset = self.getOffsetFromRva(symNameAddr)

		// Ordinal
		sym.OrdinalOffset = startAddrOfOrdinals + (i * 2)
		if err = self.parseHeader(&sym.Ordinal, sym.OrdinalOffset, 2); err != nil {
			return err
		}
			
		// Address
		sym.AddressOffset = startAddrOfFuncs + (uint32(sym.Ordinal) * 4)
		if err = self.parseHeader(&sym.Address, sym.AddressOffset, 4); err != nil {
			return err
		}
		if sym.Address == 0 {
			continue
		}

		// Forwarder if applicable
		if sym.Address >= rva && sym.Address < rva + size {
			sym.Forwarder = self.getStringAtRva(sym.Address)
			sym.ForwarderOffset = self.getOffsetFromRva(sym.Address)
		}

		sym.Ordinal += uint16(exportDir.Data.Base)

		ordMap[sym.Ordinal] = true
		exportDir.Exports = append(exportDir.Exports, sym)
	}

	// Check for any missing function symbols
	section = self.getSectionByRva(exportDir.Data.AddressOfFunctions)
	if section == nil {
		log.Printf(errMsg, "AddressOfFunctions", exportDir.Data.AddressOfFunctions)
		return errors.New(fmt.Sprintf(errMsg, "AddressOfFunctions", exportDir.Data.AddressOfFunctions))
	}
	safetyBoundary = section.Data.VirtualAddress + section.Data.SizeOfRawData - exportDir.Data.AddressOfFunctions
	numNames = Min(safetyBoundary / 4, exportDir.Data.NumberOfFunctions)

	fmt.Printf("Safety2 boundary %x, num names %d\n", safetyBoundary, numNames)
	for i := uint32(0); i < numNames; i ++ {
		if _, ok := ordMap[uint16(i + exportDir.Data.Base)]; ok {
			continue
		}

		sym := new(lib.ExportData)

		// Address
		sym.AddressOffset = startAddrOfFuncs + (uint32(sym.Ordinal) * 4)
		if err = self.parseHeader(&sym.Address, sym.AddressOffset, 4); err != nil {
			return err
		}
		if sym.Address == 0 {
			continue
		}

		// Forwarder if applicable
		if sym.Address >= rva && sym.Address < rva + size {
			sym.Forwarder = self.getStringAtRva(sym.Address)
			sym.ForwarderOffset = self.getOffsetFromRva(sym.Address)
		}

		sym.Ordinal = uint16(exportDir.Data.Base + i)

		exportDir.Exports = append(exportDir.Exports, sym)

	}
	return nil
}