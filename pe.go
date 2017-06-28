package pefile

/*
  TODO: figure out how to detect endianess instead of forcing LittleEndian
*/
import (
	"errors"
	"fmt"
	"github.com/edsrzf/mmap-go"
	"log"
	"os"
	"sort"
)

// PEFile is a representation of the PE/COFF file with some helpful abstractions
type PEFile struct {
	Filename          string
	DosHeader         DosHeader
	NTHeader          NTHeader
	COFFFileHeader    COFFFileHeader
	OptionalHeader    *OptionalHeader
	OptionalHeader64  *OptionalHeader64
	Sections          []SectionHeader
	ImportDescriptors []ImportDescriptor
	ExportDirectory   *ExportDirectory
	Errors            []error
	// Private Fields
	data mmap.MMap
	// dataLen is a convience field that holds len(data) as a uint32
	dataLen   uint32
	headerEnd uint32
}

// NewPEFile attempt to parse a PE file from a file on disk, using mmap
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

	pe.DosHeader = newDosHeader(uint32(0x0))
	if err = pe.readOffset(&pe.DosHeader.Data, offset); err != nil {
		return nil, err
	}

	if pe.DosHeader.Data.E_magic == IMAGE_DOSZM_SIGNATURE {
		return nil, errors.New("Probably a ZM Executable (not a PE file)")
	}

	if pe.DosHeader.Data.E_magic != IMAGE_DOS_SIGNATURE {
		return nil, errors.New("DOS Header magic not found")
	}

	if pe.DosHeader.Data.E_lfanew > pe.dataLen {
		return nil, errors.New("Invalid e_lfanew value, probably not a PE file")
	}

	offset = pe.DosHeader.Data.E_lfanew

	pe.NTHeader = newNTHeader(offset)
	if err = pe.readOffset(&pe.NTHeader.Data, offset); err != nil {
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

	pe.COFFFileHeader = newCOFFFileHeader(offset)
	if err = pe.readOffset(&pe.COFFFileHeader.Data, offset); err != nil {
		return nil, err
	}
	SetFlags(pe.COFFFileHeader.Flags, ImageCharacteristics, uint32(pe.COFFFileHeader.Data.Characteristics))

	offset += pe.COFFFileHeader.Size

	pe.OptionalHeader = newOptionalHeader(offset)
	if err = pe.readOffset(&pe.OptionalHeader.Data, offset); err != nil {
		return nil, err
	}
	SetFlags(pe.OptionalHeader.Flags, DllCharacteristics, uint32(pe.OptionalHeader.Data.DllCharacteristics))

	if pe.OptionalHeader.Data.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS {
		pe.OptionalHeader64 = newOptionalHeader64(offset)
		if err = pe.readOffset(&pe.OptionalHeader64.Data, offset); err != nil {
			return nil, err
		}

		if pe.OptionalHeader64.Data.Magic != OPTIONAL_HEADER_MAGIC_PE_PLUS {
			return nil, errors.New("No Optional Header found, invalid PE32 or PE32+ file")
		}
		SetFlags(pe.OptionalHeader64.Flags, DllCharacteristics, uint32(pe.OptionalHeader64.Data.DllCharacteristics))
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

	var dataDir map[string]DataDirectory

	sectionOffset := offset + uint32(pe.COFFFileHeader.Data.SizeOfOptionalHeader)

	if pe.OptionalHeader64 != nil {
		if pe.OptionalHeader64.Data.NumberOfRvaAndSizes > 0x10 {
			log.Printf(msg, pe.OptionalHeader64.Data.NumberOfRvaAndSizes)
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

	for i := uint32(0); i < 0x7fffffff&numRvaAndSizes; i++ {

		if pe.dataLen-offset == 0 {
			break
		}

		dirEntry := newDataDirectory(offset)
		if err = pe.readOffset(&dirEntry.Data, offset); err != nil {
			return nil, err
		}
		offset += dirEntry.Size
		name, ok := DirectoryEntryTypes[i]

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

	_, err = pe.getOffsetFromRva(pe.OptionalHeader.Data.AddressOfEntryPoint)
	if err != nil {
		log.Printf("Possibly corrupt file. AddressOfEntryPoint lies outside the file. AddressOfEntryPoint: 0x%x, %s", pe.OptionalHeader.Data.AddressOfEntryPoint, err)
	}

	err = pe.parseDataDirectories()
	if err != nil {
		return nil, err
	}
	/*offset, err = pe.parseRichHeader()
	if err != nil {
		return nil, err
	}*/

	return pe, nil
}

// ByVAddr is a helper for sorting sections by VirtualAddress
type byVAddr []SectionHeader

func (bva byVAddr) Len() int {
	return len(bva)
}
func (bva byVAddr) Swap(i, j int) {
	bva[i], bva[j] = bva[j], bva[i]
}
func (bva byVAddr) Less(i, j int) bool {
	return bva[i].Data.VirtualAddress < bva[j].Data.VirtualAddress
}

func (pe *PEFile) parseSections(offset uint32) (newOffset uint32, err error) {
	newOffset = offset
	for i := uint32(0); i < uint32(pe.COFFFileHeader.Data.NumberOfSections); i++ {
		section := newSectionHeader(newOffset)
		if err = pe.readOffset(&section.Data, newOffset); err != nil {
			return 0, err
		}

		// TODO: More checks and error handling here from parseSections
		// L2325-2376

		SetFlags(section.Flags, SectionCharacteristics, uint32(section.Data.Characteristics))

		// Suspecious check L2383 - L2395
		pe.Sections = append(pe.Sections, section)

		newOffset += section.Size
	}

	// Sort the sections by their VirtualAddress and add a field to each of them
	// with the VirtualAddress of the next section. This will allow to check
	// for potentially overlapping sections in badly constructed PEs.
	sort.Sort(byVAddr(pe.Sections))
	for idx, section := range pe.Sections {
		if idx == len(pe.Sections)-1 {
			section.NextHeaderAddr = 0
		} else {
			section.NextHeaderAddr = pe.Sections[idx+1].Data.VirtualAddress
		}
	}

	return newOffset, nil
}

func (pe *PEFile) parseDataDirectories() error {
	var dataDirs map[string]DataDirectory

	funcMap := map[string]interface{}{
		"IMAGE_DIRECTORY_ENTRY_IMPORT": pe.parseImportDirectory,
		"IMAGE_DIRECTORY_ENTRY_EXPORT": pe.parseExportDirectory,
		//"IMAGE_DIRECTORY_ENTRY_RESOURCE": pe.parse_resources_directory,

		// TODO at a later time
		//"IMAGE_DIRECTORY_ENTRY_DEBUG": pe.parseDebugDirectory,
		//"IMAGE_DIRECTORY_ENTRY_BASERELOC": pe.parseRelocationsDirectory,
		//"IMAGE_DIRECTORY_ENTRY_TLS": pe.parseDirectoryTls,
		//"IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG": pe.parseDirectoryLoadConfig,
		//"IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT": pe.parseDelayImportDirectory,
		//"IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT": pe.parseDirectoryBoundImports,
	}

	if pe.OptionalHeader64 != nil {
		dataDirs = pe.OptionalHeader64.DataDirs
	} else {
		dataDirs = pe.OptionalHeader.DataDirs
	}
	for name, dirEntry := range dataDirs {
		if dirEntry.Data.VirtualAddress > 0 {
			parser, ok := funcMap[name]
			if !ok {
				continue
			}
			err := parser.(func(uint32, uint32) error)(dirEntry.Data.VirtualAddress, dirEntry.Data.Size)
			if err != nil {
				pe.Errors = append(pe.Errors, err)
			}
		}
	}

	return nil
}

func (pe *PEFile) getSectionByRva(rva uint32) *SectionHeader {
	for _, section := range pe.Sections {
		var size uint32
		adjustedPointer := pe.adjustFileAlignment(section.Data.PointerToRawData)
		if pe.dataLen-adjustedPointer < section.Data.SizeOfRawData {
			size = section.Data.Misc
		} else {
			size = max(section.Data.SizeOfRawData, section.Data.Misc)
		}
		vaddr := pe.adjustSectionAlignment(section.Data.VirtualAddress)

		if section.NextHeaderAddr != 0 && section.NextHeaderAddr > section.Data.VirtualAddress && vaddr+size > section.NextHeaderAddr {
			size = section.NextHeaderAddr - vaddr
		}

		if vaddr <= rva && rva < (vaddr+size) {
			return &section
		}
	}
	return nil
}

func (pe *PEFile) getSectionByOffset(offset uint32) *SectionHeader {
	for _, section := range pe.Sections {
		if section.Data.PointerToRawData == 0 {
			continue
		}

		adjustedPointer := pe.adjustFileAlignment(section.Data.PointerToRawData)
		if adjustedPointer <= offset && offset < (adjustedPointer+section.Data.SizeOfRawData) {
			return &section
		}
	}
	return nil
}

func (pe *PEFile) getRvaFromOffset(offset uint32) uint32 {
	section := pe.getSectionByOffset(offset)
	minAddr := ^uint32(0)
	if section == nil {

		if len(pe.Sections) == 0 {
			return offset
		}

		for _, section := range pe.Sections {
			vaddr := pe.adjustSectionAlignment(section.Data.VirtualAddress)
			if vaddr < minAddr {
				minAddr = vaddr
			}
		}
		// Assume that offset lies within the headers
		// The case illustrating this behavior can be found at:
		// http://corkami.blogspot.com/2010/01/hey-hey-hey-whats-in-your-head.html
		// where the import table is not contained by any section
		// hence the RVA needs to be resolved to a raw offset
		if offset < minAddr {
			return offset
		}

		log.Println("data at Offset can't be fetched. Corrupt header?")
		return ^uint32(0)
	}
	sectionAlignment := pe.adjustSectionAlignment(section.Data.VirtualAddress)
	fileAlignment := pe.adjustFileAlignment(section.Data.PointerToRawData)
	return offset - fileAlignment + sectionAlignment
}

func (pe *PEFile) getOffsetFromRva(rva uint32) (uint32, error) {
	section := pe.getSectionByRva(rva)
	if section == nil {
		if rva < pe.dataLen {
			log.Printf("No section for rva 0x%x, but less than file length, passing back", rva)
			return rva, nil
		}
		return 0, fmt.Errorf("RVA 0x%x can't be mapped to a file offset. Corrupt header?", rva)
	}
	sectionAlignment := pe.adjustSectionAlignment(section.Data.VirtualAddress)
	fileAlignment := pe.adjustFileAlignment(section.Data.PointerToRawData)
	return rva - sectionAlignment + fileAlignment, nil
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
func (pe *PEFile) adjustFileAlignment(pointer uint32) uint32 {
	fileAlignment := pe.OptionalHeader.Data.FileAlignment

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
func (pe *PEFile) adjustSectionAlignment(pointer uint32) uint32 {
	sectionAlignment := pe.OptionalHeader.Data.SectionAlignment
	fileAlignment := pe.OptionalHeader.Data.FileAlignment
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

	if sectionAlignment != 0 && (pointer%sectionAlignment) != 0 {
		return sectionAlignment * (pointer / sectionAlignment)
	}
	return pointer
}

// getDataBounds returns a start file offset and a max length:
// * if rva is in a valid section, from the file offset of the rva to end of
//   of the section, or less if length is non-zero
func (pe *PEFile) getDataBounds(rva uint32) (start, length uint32, err error) {
	section := pe.getSectionByRva(rva)

	if section == nil {
		if rva < pe.headerEnd {
			return rva, pe.headerEnd, nil
		}
		// Before we give up we check whether the file might
		// contain the data anyway. There are cases of PE files
		// without sections that rely on windows loading the first
		// 8291 bytes into memory and assume the data will be
		// there
		// A functional file with these characteristics is:
		// MD5: 0008892cdfbc3bda5ce047c565e52295
		// SHA-1: c7116b9ff950f86af256defb95b5d4859d4752a9
		if rva < pe.dataLen {
			return rva, pe.dataLen, nil
		}
		return 0, 0, fmt.Errorf("No valid bounds for rva 0x%x", rva)
	}

	sectionAlignment := pe.adjustSectionAlignment(section.Data.VirtualAddress)
	fileAlignment := pe.adjustFileAlignment(section.Data.PointerToRawData)
	start = rva - sectionAlignment + fileAlignment

	length = section.Data.VirtualAddress + section.Data.SizeOfRawData - rva

	return
}

// OC Patch:
// There could be a problem if there are no raw data sections
// greater than 0
// fc91013eb72529da005110a3403541b6 example
// Should this throw an exception in the minimum header offset
// can't be found?
func (pe *PEFile) calculateHeaderEnd(offset uint32) {
	var rawDataPointers []uint32
	for _, section := range pe.Sections {
		prd := section.Data.PointerToRawData
		if prd > uint32(0x0) {
			rawDataPointers = append(rawDataPointers, pe.adjustFileAlignment(prd))
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
		pe.headerEnd = offset
	} else {
		pe.headerEnd = minSectionOffset
	}
}
