package pe

/* 
  TODO: figure out how to detect endianess instead of forcing LittleEndian
*/
import (
	"../lib"
	"log"
	mmap "github.com/edsrzf/mmap-go"
	"os"
	"bytes"
	"sort"
	"encoding/binary"
	"errors"
)


/* The representation of the PEFile with some helpful abstractions */
type PEFile struct {
	Filename			string
	DosHeader			*lib.DosHeader
	NTHeader			*lib.NTHeader
	FileHeader			*lib.FileHeader
	OptionalHeader		*lib.OptionalHeader
	OptionalHeader64	*lib.OptionalHeader64
	Sections 			[]*lib.SectionHeader
	ImportDescriptors	[]*lib.ImportDescriptor
	ExportDirectory     *lib.ExportDirectory
	// Private Fields
	data				mmap.MMap
	dataLen				uint32
	headerEnd			uint32
}

func NewPEFile(filename string) (pe *PEFile, err error) {
	pe = new(PEFile)
	pe.Filename = filename
	var offset = uint32(0)

	handle, err := os.Open(pe.Filename)
	if err != nil {
		return nil, err
	}
	pe.data, err = mmap.Map(handle, mmap.RDONLY, 0)
	if err != nil {
		return nil, err
	}

	pe.dataLen = uint32(len(pe.data))

	pe.DosHeader = lib.NewDosHeader(uint32(0x0))
	if err = pe.parseHeader(&pe.DosHeader.Data, offset, pe.DosHeader.Size); err != nil {
		return nil, err
	}

	if pe.DosHeader.Data.E_magic == IMAGE_DOSZM_SIGNATURE {
		return nil, errors.New("Probably a ZM Executable (not a PE file).")
	}
	
	if pe.DosHeader.Data.E_magic != IMAGE_DOS_SIGNATURE {
		return nil, errors.New("DOS Header magic not found.")
	}

	if pe.DosHeader.Data.E_lfanew > pe.dataLen {
		return nil, errors.New("Invalid e_lfanew value, probably not a PE file")
	}
	
	offset = pe.DosHeader.Data.E_lfanew

	pe.NTHeader = lib.NewNTHeader(offset)
	if err = pe.parseHeader(&pe.NTHeader.Data, offset, pe.NTHeader.Size); err != nil {
		return nil, err
	}

	if (0xFFFF & pe.NTHeader.Data.Signature) == IMAGE_NE_SIGNATURE {
		return nil, errors.New("Invalid NT Headers signature. Probably a NE file")
	} else if (0xFFFF & pe.NTHeader.Data.Signature) == IMAGE_LE_SIGNATURE {
		return nil, errors.New("Invalid NT Headers signature. Probably a LE file")
	} else if (0xFFFF & pe.NTHeader.Data.Signature) == IMAGE_LX_SIGNATURE {
		return nil, errors.New("Invalid NT Headers signature. Probably a LX file")
	} else if (0xFFFF & pe.NTHeader.Data.Signature) == IMAGE_TE_SIGNATURE {
		return nil, errors.New("Invalid NT Headers signature. Probably a TE file")
	} else if pe.NTHeader.Data.Signature != IMAGE_NT_SIGNATURE {
		return nil, errors.New("Invalid NT Headers signature.")
	}

	offset += pe.NTHeader.Size

	pe.FileHeader = lib.NewFileHeader(offset)
	if err = pe.parseHeader(&pe.FileHeader.Data, offset, pe.FileHeader.Size); err != nil {
		return nil, err
	}
	lib.SetFlags(pe.FileHeader.Flags, lib.ImageCharacteristics, uint32(pe.FileHeader.Data.Characteristics))

	offset += pe.FileHeader.Size

	log.Println("Size of OptionalHeader")

	pe.OptionalHeader = lib.NewOptionalHeader(offset)
	if err = pe.parseHeader(&pe.OptionalHeader.Data, offset, pe.OptionalHeader.Size); err != nil {
		return nil, err
	}
	lib.SetFlags(pe.OptionalHeader.Flags, lib.DllCharacteristics, uint32(pe.OptionalHeader.Data.DllCharacteristics))

	if pe.OptionalHeader.Data.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS {
		pe.OptionalHeader64 = lib.NewOptionalHeader64(offset)
		if err = pe.parseHeader(&pe.OptionalHeader64.Data, offset, pe.OptionalHeader64.Size); err != nil {
			return nil, err
		}

		if pe.OptionalHeader64.Data.Magic != OPTIONAL_HEADER_MAGIC_PE_PLUS {
			return nil, errors.New("No Optional Header found, invalid PE32 or PE32+ file")
		}
		lib.SetFlags(pe.OptionalHeader64.Flags, lib.DllCharacteristics, uint32(pe.OptionalHeader64.Data.DllCharacteristics))
	}

	// Windows 8 specific check
	//
	if pe.OptionalHeader.Data.AddressOfEntryPoint < pe.OptionalHeader.Data.SizeOfHeaders {
		log.Println("Warning: SizeOfHeaders is smaller than AddressOfEntryPoint: this file cannot run under Windows 8")
	}

	// Section data
	//MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES := 0x100
	var numRvaAndSizes uint32
	
	msg := "Suspicious NumberOfRvaAndSizes in the Optional Header."
	msg += "Normal values are never larger than 0x10, the value is: 0x%x\n"

	var dataDir map[string]*lib.DataDirectory

	sectionOffset := offset + uint32(pe.FileHeader.Data.SizeOfOptionalHeader)

	if pe.OptionalHeader64 != nil {
		if pe.OptionalHeader64.Data.NumberOfRvaAndSizes > 0x10 {
			log.Printf(msg,	pe.OptionalHeader64.Data.NumberOfRvaAndSizes)
		}
		numRvaAndSizes = pe.OptionalHeader64.Data.NumberOfRvaAndSizes
		offset += pe.OptionalHeader64.Size
		dataDir = pe.OptionalHeader64.DataDirs

	} else {
		if pe.OptionalHeader.Data.NumberOfRvaAndSizes > 0x10 {
			log.Printf(msg, pe.OptionalHeader.Data.NumberOfRvaAndSizes)
		}
		numRvaAndSizes = pe.OptionalHeader.Data.NumberOfRvaAndSizes
		offset += pe.OptionalHeader.Size
		dataDir = pe.OptionalHeader.DataDirs
	}
	
	for i := uint32(0); i < 0x7fffffff & numRvaAndSizes; i ++ {

		if pe.dataLen - offset == 0 {
			break
		}

		dirEntry := lib.NewDataDirectory(offset)
		if err = pe.parseHeader(&dirEntry.Data, offset, dirEntry.Size); err != nil {
			return nil, err
		}
		offset += dirEntry.Size
		name, ok := lib.DirectoryEntryTypes[i]
		
		dirEntry.Name = name
		
		if !ok {
			break
		}
		dataDir[dirEntry.Name] = dirEntry
		// TODO: add skipped check at L2038
	}

	offset, err = pe.parseSections(sectionOffset)
	if err != nil {
		return nil, err
	}

	pe.calculateHeaderEnd(offset)

	if pe.getSectionByRva(pe.OptionalHeader.Data.AddressOfEntryPoint) != nil {
		epOffset := pe.getOffsetFromRva(pe.OptionalHeader.Data.AddressOfEntryPoint)
		if epOffset > pe.dataLen {
			log.Printf("Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint: 0x%x", pe.OptionalHeader.Data.AddressOfEntryPoint)
		}
	} else {
		log.Printf("AddressOfEntryPoint lies outside the sections' boundaries, AddressOfEntryPoint: 0x%x", pe.OptionalHeader.Data.AddressOfEntryPoint)
	}

	err = pe.parseDataDirectories()
	if err != nil {
		return nil , err
	}
	/*offset, err = pe.parseRichHeader()
	if err != nil {
		return nil, err
	}*/

	return pe, nil
}

type ByVAddr []*lib.SectionHeader
func (self ByVAddr) Len() int {
	return len(self)
}
func (self ByVAddr) Swap(i, j int) {
	self[i], self[j] = self[j], self[i]
}
func (s ByVAddr) Less(i, j int) bool {
	return s[i].Data.VirtualAddress < s[j].Data.VirtualAddress
}

func (self *PEFile) parseSections(offset uint32) (newOffset uint32, err error) {
	newOffset = offset
	for i := uint32(0); i < uint32(self.FileHeader.Data.NumberOfSections); i ++ {
		section := lib.NewSectionHeader(newOffset)
		if err = self.parseHeader(&section.Data, newOffset, section.Size); err != nil {
			return 0, err
		}

		// TODO: More checks and error handling here from parseSections
		// L2325-2376

		lib.SetFlags(section.Flags, lib.SectionCharacteristics, uint32(section.Data.Characteristics))

		// Suspecious check L2383 - L2395
		self.Sections = append(self.Sections, section)
		
		newOffset += section.Size
	}
	
	// Sort the sections by their VirtualAddress and add a field to each of them
	// with the VirtualAddress of the next section. This will allow to check
	// for potentially overlapping sections in badly constructed PEs.
	sort.Sort(ByVAddr(self.Sections))
	for idx, section := range self.Sections {
		if idx == len(self.Sections) - 1 {
			section.NextHeaderAddr = 0
		} else {
			section.NextHeaderAddr = self.Sections[idx + 1].Data.VirtualAddress
		}
	}

	return newOffset, nil
}

func (self *PEFile) parseHeader(iface interface{}, offset, size uint32) (err error) {
	buf := bytes.NewReader(self.data[offset : offset + size])
	err = binary.Read(buf, binary.LittleEndian, iface)
	if err != nil {
		return err
	}
	return nil
}

func (self *PEFile) parseDataDirectories() error {
	var dataDirs map[string]*lib.DataDirectory

	funcMap := map[string]interface{}{
		"IMAGE_DIRECTORY_ENTRY_IMPORT": self.parseImportDirectory,
		"IMAGE_DIRECTORY_ENTRY_EXPORT": self.parseExportDirectory,
		//"IMAGE_DIRECTORY_ENTRY_RESOURCE": self.parse_resources_directory,
		
		// TODO at a later time
		//"IMAGE_DIRECTORY_ENTRY_DEBUG": self.parseDebugDirectory,
		//"IMAGE_DIRECTORY_ENTRY_BASERELOC": self.parseRelocationsDirectory,
		//"IMAGE_DIRECTORY_ENTRY_TLS": self.parseDirectoryTls,
		//"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": self.parseDirectoryLoadConfig,
		//"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": self.parseDelayImportDirectory,
		//"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": self.parseDirectoryBoundImports,
	}

	if self.OptionalHeader64 != nil {
		dataDirs = self.OptionalHeader64.DataDirs
	} else {
		dataDirs = self.OptionalHeader.DataDirs
	}
	for name, dirEntry := range dataDirs {
		if dirEntry.Data.VirtualAddress > 0 {
			parser, ok := funcMap[name] 
			if !ok { continue }
			err := parser.(func(uint32, uint32) error)(dirEntry.Data.VirtualAddress, dirEntry.Data.Size)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (self *PEFile) getSectionByRva(rva uint32) *lib.SectionHeader {
	for _, section := range self.Sections {
		var size uint32
		adjustedPointer := self.adjustFileAlignment(section.Data.PointerToRawData)
		if self.dataLen - adjustedPointer < section.Data.SizeOfRawData {
			size = section.Data.Misc
		} else {
			size = Max(section.Data.SizeOfRawData, section.Data.Misc)
		}
		vaddr := self.adjustSectionAlignment(section.Data.VirtualAddress)

		if section.NextHeaderAddr != 0 && section.NextHeaderAddr > section.Data.VirtualAddress && vaddr + size > section.NextHeaderAddr {
			size = section.NextHeaderAddr - vaddr
		}

		if vaddr <= rva && rva < (vaddr + size) {
			return section
		}
	}
	return nil
}

func (self *PEFile) getSectionByOffset(offset uint32) *lib.SectionHeader {
	for _, section := range self.Sections {
		if section.Data.PointerToRawData == 0 { continue }
		
		adjustedPointer := self.adjustFileAlignment(section.Data.PointerToRawData)
		if adjustedPointer <= offset && offset < (adjustedPointer + section.Data.SizeOfRawData) {
			return section
		}
	}
	return nil
}

func (self *PEFile) getRvaFromOffset(offset uint32) uint32 {
	section := self.getSectionByOffset(offset)
	minAddr := ^uint32(0)
	if section == nil {

		if len(self.Sections) == 0 { return offset }

		for _, section := range self.Sections {
			vaddr := self.adjustSectionAlignment(section.Data.VirtualAddress)
			if vaddr < minAddr {
				minAddr = vaddr
			}
		}
		// Assume that offset lies within the headers
		// The case illustrating this behavior can be found at:
		// http://corkami.blogspot.com/2010/01/hey-hey-hey-whats-in-your-head.html
		// where the import table is not contained by any section
		// hence the RVA needs to be resolved to a raw offset
		if offset < minAddr { return offset }

		log.Println("data at Offset can't be fetched. Corrupt header?")
		return ^uint32(0)
	}
	sectionAlignment := self.adjustSectionAlignment(section.Data.VirtualAddress)
	fileAlignment := self.adjustFileAlignment(section.Data.PointerToRawData)
	return offset - fileAlignment + sectionAlignment
}

func (self *PEFile) getOffsetFromRva(rva uint32) uint32 {
	section := self.getSectionByRva(rva)
	if section == nil {
		if rva < self.dataLen {
			return rva
		}
		log.Println("data at RVA can't be fetched. Corrupt header?")
		return ^uint32(0)
	}
	sectionAlignment := self.adjustSectionAlignment(section.Data.VirtualAddress)
	fileAlignment := self.adjustFileAlignment(section.Data.PointerToRawData)
	return rva - sectionAlignment + fileAlignment
}

// According to http://corkami.blogspot.com/2010/01/parce-que-la-planche-aura-brule.html
// if PointerToRawData is less that 0x200 it's rounded to zero. Loading the test file
// in a debugger it's easy to verify that the PointerToRawData value of 1 is rounded
// to zero. Hence we reproduce the behavior
//
// According to the document:
// [ Microsoft Portable Executable and Common Object File Format Specification ]
// "The alignment factor (in bytes) that is used to align the raw data of sections in
//  the image file. The value should be a power of 2 between 512 and 64 K, inclusive.
//  The default is 512. If the SectionAlignment is less than the architecture's page
//  size, then FileAlignment must match SectionAlignment."
//
// The following is a hard-coded constant if the Windows loader
func (self *PEFile) adjustFileAlignment(pointer uint32) uint32 {
	fileAlignment := self.OptionalHeader.Data.FileAlignment
		
	if fileAlignment > FILE_ALIGNMENT_HARDCODED_VALUE {
		// If it's not a power of two, report it:
		if !PowerOfTwo(fileAlignment) {
			log.Printf("If FileAlignment > 0x200 it should be a power of 2. Value: %x", fileAlignment)
		}
	}

	if fileAlignment < FILE_ALIGNMENT_HARDCODED_VALUE {
		return pointer
	}
	return (pointer / 0x200) * 0x200
}

// According to the document:
// [ Microsoft Portable Executable and Common Object File Format Specification ]
// "The alignment (in bytes) of sections when they are loaded into memory. It must be
//  greater than or equal to FileAlignment. The default is the page size for the
//  architecture."
//
func (self *PEFile) adjustSectionAlignment(pointer uint32) uint32 {
	sectionAlignment := self.OptionalHeader.Data.SectionAlignment
	fileAlignment := self.OptionalHeader.Data.FileAlignment
	if fileAlignment < FILE_ALIGNMENT_HARDCODED_VALUE {
		if fileAlignment != sectionAlignment {
			log.Printf("If FileAlignment(%x) < 0x200 it should equal SectionAlignment(%x)", fileAlignment, sectionAlignment)
		}
	}
	if sectionAlignment < 0x1000 { // page size
		sectionAlignment = fileAlignment
	}
	// else if sectionAlignment < 0x80 {
		// 0x200 is the minimum valid FileAlignment according to the documentation
		// although ntoskrnl.exe has an alignment of 0x80 in some Windows versions
	//	sectionAlignment = 0x80
	//}

	if sectionAlignment != 0 && (pointer % sectionAlignment) != 0 {
		return sectionAlignment * ( pointer / sectionAlignment )
	}
	return pointer
}

func (self *PEFile) getDataBounds(rva, length uint32) (start, size uint32) {
	var end uint32
	var offset uint32

	section := self.getSectionByRva(rva)

	if length > 0 {
		end = rva + length
	} else {
		end = self.dataLen
	}
	if section == nil {
		if rva < self.headerEnd {
			end = Min(end, self.headerEnd)
		}
		// Before we give up we check whether the file might
		// contain the data anyway. There are cases of PE files
		// without sections that rely on windows loading the first
		// 8291 bytes into memory and assume the data will be
		// there
		// A functional file with these characteristics is:
		// MD5: 0008892cdfbc3bda5ce047c565e52295
		// SHA-1: c7116b9ff950f86af256defb95b5d4859d4752a9
		if rva < self.dataLen {
			return rva, end
		}
		return ^uint32(0), ^uint32(0)
	}
	pointer := self.adjustFileAlignment(section.Data.PointerToRawData)
	vaddr := self.adjustSectionAlignment(section.Data.VirtualAddress)

	if rva == 0 {
		offset = pointer
	} else {
		offset = (rva - vaddr) + pointer
	}
	if length != 0 {
		end = offset + length
	} else {
		end = offset + section.Data.SizeOfRawData
	}
	if end > pointer + section.Data.SizeOfRawData {
		end = section.Data.PointerToRawData + section.Data.SizeOfRawData
	}
	return offset, end
}

// Get an ASCII string from within the data at an RVA considering 
// section 
func (self *PEFile) getStringAtRva(rva uint32) []byte {
	start, _ := self.getDataBounds(rva, 0)
	return self.getStringFromData(start)
}

// Get an ASCII string from within the data.
func (self *PEFile) getStringFromData(offset uint32) []byte {
	if offset > self.dataLen {
		return []byte{}
	}

	end := offset
	for end < self.dataLen {
		if self.data[end] == 0 {
			break
		}
		end += 1
	}
	return self.data[offset:end]
}

// OC Patch:
// There could be a problem if there are no raw data sections
// greater than 0
// fc91013eb72529da005110a3403541b6 example
// Should this throw an exception in the minimum header offset
// can't be found?		
func (self *PEFile) calculateHeaderEnd(offset uint32) {
	var rawDataPointers []uint32
	for _, section := range self.Sections {
		prd := section.Data.PointerToRawData
		if prd > uint32(0x0) {
			rawDataPointers = append(rawDataPointers, self.adjustFileAlignment(prd))
		}
	}
	minSectionOffset := uint32(0x0)
	if len(rawDataPointers) > 0 {
		minSectionOffset = rawDataPointers[0]
		for _, pointer := range rawDataPointers {
			if pointer < minSectionOffset {
				minSectionOffset = pointer
			}
		}
	}
	if minSectionOffset == 0 || minSectionOffset < offset {
		self.headerEnd = offset
	} else {
		self.headerEnd = minSectionOffset
	}
}

