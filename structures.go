package pefile

import (
	"encoding/binary"
	"fmt"
	"reflect"
)

/* Dos Header */

// DosHeader wrapper
type DosHeader struct {
	Data       DosHeaderD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newDosHeader(fileOffset uint32) DosHeader {
	return DosHeader{
		Flags:      make(map[string]bool),
		Size:       uint32(binary.Size(DosHeaderD{})),
		FileOffset: fileOffset,
	}
}

func (dh *DosHeader) String() string {
	return sectionString(dh.FileOffset, "IMAGE_DOS_HEADER", dh.Data) + flagString(dh.Flags)
}

// DosHeaderD raw data field read from the file
type DosHeaderD struct {
	E_magic    uint16
	E_cblp     uint16
	E_cp       uint16
	E_crlc     uint16
	E_cparhd   uint16
	E_minalloc uint16
	E_maxalloc uint16
	E_ss       uint16
	E_sp       uint16
	E_csum     uint16
	E_ip       uint16
	E_cs       uint16
	E_lfarlc   uint16
	E_ovno     uint16
	E_res      [8]uint8
	E_oemid    uint16
	E_oeminfo  uint16
	E_res2     [20]uint8
	E_lfanew   uint32
}

// NTHeader wrapper
type NTHeader struct {
	Data       NTHeaderD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newNTHeader(fileOffset uint32) NTHeader {
	return NTHeader{
		Flags:      make(map[string]bool),
		Size:       uint32(binary.Size(NTHeaderD{})),
		FileOffset: fileOffset,
	}
}

// NTHeaderD raw data field read from the file
type NTHeaderD struct {
	Signature uint32
}

func (nth *NTHeader) String() string {
	return sectionString(nth.FileOffset, "IMAGE_NT_HEADER", nth.Data) + flagString(nth.Flags)
}

// COFFFileHeader wrapper
type COFFFileHeader struct {
	Data       COFFFileHeaderD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newCOFFFileHeader(fileOffset uint32) COFFFileHeader {
	return COFFFileHeader{
		Flags:      make(map[string]bool),
		Size:       uint32(binary.Size(COFFFileHeaderD{})),
		FileOffset: fileOffset,
	}
}

func (fh *COFFFileHeader) String() string {
	return sectionString(fh.FileOffset, "COFF_FILE_HEADER", fh.Data) + flagString(fh.Flags)
}

// COFFFileHeaderD raw data field read from the file
type COFFFileHeaderD struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// OptionalHeader wrapper
type OptionalHeader struct {
	Data       OptionalHeaderD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
	DataDirs   map[string]DataDirectory
}

func newOptionalHeader(fileOffset uint32) (header *OptionalHeader) {
	header = new(OptionalHeader)
	header.Flags = make(map[string]bool)
	header.DataDirs = make(map[string]DataDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (od *OptionalHeader) String() string {
	return sectionString(od.FileOffset, "OPTIONAL_HEADER", od.Data) + flagString(od.Flags)
}

// OptionalHeaderD raw data field read from the file
type OptionalHeaderD struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Reserved1                   uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// OptionalHeader64 wrapper
type OptionalHeader64 struct {
	Data       OptionalHeader64D
	FileOffset uint32
	Flags      map[string]bool
	DataDirs   map[string]DataDirectory
	Size       uint32
}

func newOptionalHeader64(fileOffset uint32) (header *OptionalHeader64) {
	header = new(OptionalHeader64)
	header.Flags = make(map[string]bool)
	header.DataDirs = make(map[string]DataDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (oh *OptionalHeader64) String() string {
	return sectionString(oh.FileOffset, "OPTIONAL_HEADER64", oh.Data) + flagString(oh.Flags)
}

// OptionalHeader64D raw data field read from the file
type OptionalHeader64D struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Reserved1                   uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64 // Different after this point, specific checks needed
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// DataDirectory wrapper
type DataDirectory struct {
	Data       DataDirectoryD
	FileOffset uint32
	Name       string
	Size       uint32
}

// DataDirectoryD raw data field read from the file
type DataDirectoryD struct {
	VirtualAddress uint32
	Size           uint32
}

func newDataDirectory(fileOffset uint32) (header DataDirectory) {
	return DataDirectory{
		Size:       uint32(binary.Size(DataDirectoryD{})),
		FileOffset: fileOffset,
	}
}

func (dd *DataDirectory) String() string {
	return sectionString(dd.FileOffset, "DATA_DIRECTORY", dd.Data)
}

// SectionHeader wrapper
type SectionHeader struct {
	Data           SectionHeaderD
	FileOffset     uint32
	Flags          map[string]bool
	Size           uint32
	NextHeaderAddr uint32
}

func newSectionHeader(fileOffset uint32) SectionHeader {
	var header SectionHeader
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (sh *SectionHeader) String() string {
	return sectionString(sh.FileOffset, "SECTION_HEADER", sh.Data) + flagString(sh.Flags)
}

// SectionHeaderD raw data field read from the file
type SectionHeaderD struct {
	Name                 [8]uint8
	Misc                 uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

// ImportDescriptorD raw data field read from the file
type ImportDescriptorD struct {
	Characteristics uint32
	TimeDateStamp   uint32
	ForwarderChain  uint32
	Name            uint32
	FirstThunk      uint32
}

// ImportDescriptor wrapper
type ImportDescriptor struct {
	Data       ImportDescriptorD
	FileOffset uint32
	Flags      map[string]bool
	Dll        []byte
	Imports    []ImportData
	Imports64  []ImportData64
	Size       uint32
}

func newImportDescriptor(fileOffset uint32) ImportDescriptor {
	return ImportDescriptor{
		Size:       uint32(binary.Size(ImportDescriptorD{})),
		Flags:      make(map[string]bool),
		FileOffset: fileOffset,
	}
}

func (id *ImportDescriptor) String() string {
	return sectionString(id.FileOffset, "IMPORT_DESCRIPTOR", id.Data) + flagString(id.Flags)
}

// ImportData wrapper
type ImportData struct {
	StructTable      ThunkData
	StructIat        ThunkData
	ImportByOrdinal  bool
	Ordinal          uint32
	OrdinalOffset    uint32
	Hint             uint16
	Name             []byte
	NameOffset       uint32
	Bound            uint32
	Address          uint32
	HintNameTableRva uint32
	ThunkOffset      uint32
	ThunkRva         uint32
}

func (id ImportData) String() string {
	return sectionString(0, "Import Data", id)
}

// ImportData64 64-bit version wrapper
type ImportData64 struct {
	StructTable      *ThunkData64
	StructIat        *ThunkData64
	ImportByOrdinal  bool
	Ordinal          uint64
	OrdinalOffset    uint64
	Hint             uint16
	Name             []byte
	NameOffset       uint64
	Bound            uint64
	Address          uint64
	HintNameTableRva uint64
	ThunkOffset      uint64
	ThunkRva         uint64
}

func (id ImportData64) String() string {
	return sectionString(0, "Import Data 64bit", id)
}

// DelayImportDescriptor wrapper
type DelayImportDescriptor struct {
	Data       DelayImportDescriptorD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newDelayImportDescriptor(fileOffset uint32) (header *DelayImportDescriptor) {
	header = new(DelayImportDescriptor)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (did *DelayImportDescriptor) String() string {
	return sectionString(did.FileOffset, "DELAY_IMPORT_DESCRIPTOR", did.Data) + flagString(did.Flags)
}

// DelayImportDescriptorD raw data field read from the file
type DelayImportDescriptorD struct {
	DIgrAttrs     uint32
	DIszName      uint32
	DIphmod       uint32
	DIpIAT        uint32
	DIpINT        uint32
	DIpBoundIAT   uint32
	DIpUnloadIAT  uint32
	DIdwTimeStamp uint32
}

// ExportDirectory wrapper
type ExportDirectory struct {
	Data       ExportDirectoryD
	FileOffset uint32
	Flags      map[string]bool
	Exports    []ExportData
	Size       uint32
}

func newExportDirectory(fileOffset uint32) (header *ExportDirectory) {
	header = new(ExportDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (ed *ExportDirectory) String() string {
	return sectionString(ed.FileOffset, "EXPORT_DIRECTORY", ed.Data) + flagString(ed.Flags)
}

// ExportDirectoryD raw data field read from the file
type ExportDirectoryD struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// ExportData wrapper
type ExportData struct {
	Ordinal         uint16
	OrdinalOffset   uint32
	Address         uint32
	AddressOffset   uint32
	Name            []byte //
	NameOffset      uint32 //
	Forwarder       []byte
	ForwarderOffset uint32
}

func (ed ExportData) String() string {
	return sectionString(0, "Export Data", ed)
}

// ResourceDirectory wrapper
type ResourceDirectory struct {
	Data       ResourceDirectoryD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newResourceDirectory(fileOffset uint32) (header *ResourceDirectory) {
	header = new(ResourceDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (rd *ResourceDirectory) String() string {
	return sectionString(rd.FileOffset, "RESOURCE_DIRECTORY", rd.Data) + flagString(rd.Flags)
}

// ResourceDirectoryD raw data field read from the file
type ResourceDirectoryD struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIDEntries    uint16
}

// ResourceDirectoryEntry wrapper
type ResourceDirectoryEntry struct {
	Data       ResourceDirectoryEntryD
	FileOffset uint32
	Size       uint32
}

func newResourceDirectoryEntry(fileOffset uint32) (header *ResourceDirectoryEntry) {
	header = new(ResourceDirectoryEntry)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (rde *ResourceDirectoryEntry) String() string {
	return sectionString(rde.FileOffset, "RESOURCE_DIRECTORY_ENTRY", rde.Data)
}

// ResourceDirectoryEntryD raw data field read from the file
type ResourceDirectoryEntryD struct {
	Name         uint32
	OffsetToData uint32
}

// ResourceDataEntry wrapper
type ResourceDataEntry struct {
	Data       ResourceDataEntryD
	FileOffset uint32
	Size       uint32
}

func newResourceDataEntry(fileOffset uint32) (header *ResourceDataEntry) {
	header = new(ResourceDataEntry)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (rde *ResourceDataEntry) String() string {
	return sectionString(rde.FileOffset, "RESOURCE_DATA_ENTRY", rde.Data)
}

// ResourceDataEntryD raw data field read from the file
type ResourceDataEntryD struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

// VSVersionInfo wrapper
type VSVersionInfo struct {
	Data       VSVersionInfoD
	FileOffset uint32
	Size       uint32
}

func newVSVersionInfo(fileOffset uint32) (header *VSVersionInfo) {
	header = new(VSVersionInfo)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (v *VSVersionInfo) String() string {
	return sectionString(v.FileOffset, "RESOURCE_DATA_ENTRY", v.Data)
}

// VSVersionInfoD raw data field read from the file
type VSVersionInfoD struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// VSFixedFileInfo wrapper
type VSFixedFileInfo struct {
	Data       VSFixedFileInfoD
	FileOffset uint32
	Size       uint32
}

func newVSFixedFileInfo(fileOffset uint32) (header *VSFixedFileInfo) {
	header = new(VSFixedFileInfo)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (v *VSFixedFileInfo) String() string {
	return sectionString(v.FileOffset, "VSFixedFileInfo", v.Data)
}

// VSFixedFileInfoD raw data field read from the file
type VSFixedFileInfoD struct {
	Signature        uint32
	StrucVersion     uint32
	FileVersionMS    uint32
	FileVersionLS    uint32
	ProductVersionMS uint32
	ProductVersionLS uint32
	FileFlagsMask    uint32
	FileFlags        uint32
	FileOS           uint32
	FileType         uint32
	FileSubtype      uint32
	FileDateMS       uint32
	FileDateLS       uint32
}

// StringFileInfo wrapper
type StringFileInfo struct {
	Data       StringFileInfoD
	FileOffset uint32
	Size       uint32
}

func newStringFileInfo(fileOffset uint32) (header *StringFileInfo) {
	header = new(StringFileInfo)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (s *StringFileInfo) String() string {
	return sectionString(s.FileOffset, "StringFileInfo", s.Data)
}

// StringFileInfoD raw data field read from the file
type StringFileInfoD struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// StringTable wrapper
type StringTable struct {
	Data       StringTableD
	FileOffset uint32
	Size       uint32
}

func newStringTable(fileOffset uint32) (header *StringTable) {
	header = new(StringTable)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (s *StringTable) String() string {
	return sectionString(s.FileOffset, "StringTable", s.Data)
}

// StringTableD raw data field read from the file
type StringTableD struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// String table entry wrapper
type String struct {
	Data       StringD
	FileOffset uint32
	Size       uint32
}

func newString(fileOffset uint32) (header *String) {
	header = new(String)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (s *String) String() string {
	return sectionString(s.FileOffset, "String", s.Data)
}

// StringD raw data field read from the file
type StringD struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// Var wrapper
type Var struct {
	Data       VarD
	FileOffset uint32
	Size       uint32
}

func newVar(fileOffset uint32) (header *Var) {
	header = new(Var)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (v *Var) String() string {
	return sectionString(v.FileOffset, "Var", v.Data)
}

// VarD raw data field read from the file
type VarD struct {
	Length      uint16
	ValueLength uint16
	Type        uint16
}

// ThunkData wrapper
type ThunkData struct {
	Data       ThunkDataD
	FileOffset uint32
	Size       uint32
}

func newThunkData(fileOffset uint32) (header ThunkData) {
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return
}

func (t *ThunkData) String() string {
	return sectionString(t.FileOffset, "ThunkData", t.Data)
}

// ThunkDataD raw field data read from the file
type ThunkDataD struct {
	AddressOfData uint32
}

// ThunkData64 wrapper
type ThunkData64 struct {
	Data       ThunkData64D
	FileOffset uint32
	Size       uint32
}

func newThunkData64(fileOffset uint32) (header *ThunkData64) {
	header = new(ThunkData64)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (t *ThunkData64) String() string {
	return sectionString(t.FileOffset, "ThunkData64", t.Data)
}

// ThunkData64D raw field data read from the file
type ThunkData64D struct {
	AddressOfData uint64
}

// DebugDirectory wrapper
type DebugDirectory struct {
	Data       DebugDirectoryD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newDebugDirectory(fileOffset uint32) (header *DebugDirectory) {
	header = new(DebugDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (dd *DebugDirectory) String() string {
	return sectionString(dd.FileOffset, "DebugDirectory", dd.Data) + flagString(dd.Flags)
}

// DebugDirectoryD raw field data read from the file
type DebugDirectoryD struct {
	Characteristics  uint32
	TimeDateStamp    uint32
	MajorVersion     uint16
	MinorVersion     uint16
	Type             uint32
	SizeOfData       uint32
	AddressOfRawData uint32
	PointerToRawData uint32
}

// BaseRelocation wrapper
type BaseRelocation struct {
	Data       BaseRelocationD
	FileOffset uint32
	Size       uint32
}

func newBaseRelocation(fileOffset uint32) (header *BaseRelocation) {
	header = new(BaseRelocation)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (br *BaseRelocation) String() string {
	return sectionString(br.FileOffset, "BaseRelocation", br.Data)
}

// BaseRelocationD raw field data read from the file
type BaseRelocationD struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

// BaseRelocationEntry wrapper
type BaseRelocationEntry struct {
	Data       BaseRelocationEntryD
	FileOffset uint32
	Size       uint32
}

func newBaseRelocationEntry(fileOffset uint32) (header *BaseRelocationEntry) {
	header = new(BaseRelocationEntry)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (bre *BaseRelocationEntry) String() string {
	return sectionString(bre.FileOffset, "BaseRelocationEntry", bre.Data)
}

// BaseRelocationEntryD raw field data read from the file
type BaseRelocationEntryD struct {
	Data uint16
}

// TLSDirectory wrapper
type TLSDirectory struct {
	Data       TLSDirectoryD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newTLSDirectory(fileOffset uint32) (header *TLSDirectory) {
	header = new(TLSDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (tlsd *TLSDirectory) String() string {
	return sectionString(tlsd.FileOffset, "TLSDirectory", tlsd.Data) + flagString(tlsd.Flags)
}

// TLSDirectoryD raw field data read from the file
type TLSDirectoryD struct {
	StartAddressOfRawData uint32
	EndAddressOfRawData   uint32
	AddressOfIndex        uint32
	AddressOfCallBacks    uint32
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// TLSDirectory64 wrapper
type TLSDirectory64 struct {
	Data       TLSDirectory64D
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newTLSDirectory64(fileOffset uint32) (header *TLSDirectory64) {
	header = new(TLSDirectory64)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (tlsd *TLSDirectory64) String() string {
	return sectionString(tlsd.FileOffset, "TLSDirectory64", tlsd.Data) + flagString(tlsd.Flags)
}

// TLSDirectory64D raw field data read from the file
type TLSDirectory64D struct {
	StartAddressOfRawData uint64
	EndAddressOfRawData   uint64
	AddressOfIndex        uint64
	AddressOfCallBacks    uint64
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// LoadConfigDirectory wrapper
type LoadConfigDirectory struct {
	Data       LoadConfigDirectoryD
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newLoadConfigDirectory(fileOffset uint32) (header *LoadConfigDirectory) {
	header = new(LoadConfigDirectory)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (lcd *LoadConfigDirectory) String() string {
	return sectionString(lcd.FileOffset, "LoadConfigDirectory", lcd.Data) + flagString(lcd.Flags)
}

// LoadConfigDirectoryD raw field contents read from the file
type LoadConfigDirectoryD struct {
	Size                          uint32
	TimeDateStamp                 uint32
	MajorVersion                  uint16
	MinorVersion                  uint16
	GlobalFlagsClear              uint32
	GlobalFlagsSet                uint32
	CriticalSectionDefaultTimeout uint32
	DeCommitFreeBlockThreshold    uint32
	DeCommitTotalFreeThreshold    uint32
	LockPrefixTable               uint32
	MaximumAllocationSize         uint32
	VirtualMemoryThreshold        uint32
	ProcessHeapFlags              uint32
	ProcessAffinityMask           uint32
	CSDVersion                    uint16
	Reserved1                     uint16
	EditList                      uint32
	SecurityCookie                uint32
	SEHandlerTable                uint32
	SEHandlerCount                uint32
	GuardCFCheckFunctionPointer   uint32
	Reserved2                     uint32
	GuardCFFunctionTable          uint32
	GuardCFFunctionCount          uint32
	GuardFlags                    uint32
}

// LoadConfigDirectory64 wrapper
type LoadConfigDirectory64 struct {
	Data       LoadConfigDirectory64D
	FileOffset uint32
	Flags      map[string]bool
	Size       uint32
}

func newLoadConfigDirectory64(fileOffset uint32) (header *LoadConfigDirectory64) {
	header = new(LoadConfigDirectory64)
	header.Size = uint32(binary.Size(header.Data))
	header.Flags = make(map[string]bool)
	header.FileOffset = fileOffset
	return header
}

func (lcd *LoadConfigDirectory64) String() string {
	return sectionString(lcd.FileOffset, "LoadConfigDirectory64", lcd.Data) + flagString(lcd.Flags)
}

// LoadConfigDirectory64D raw field data read from file
type LoadConfigDirectory64D struct {
	Size                          uint32
	TimeDateStamp                 uint32
	MajorVersion                  uint16
	MinorVersion                  uint16
	GlobalFlagsClear              uint32
	GlobalFlagsSet                uint32
	CriticalSectionDefaultTimeout uint32
	DeCommitFreeBlockThreshold    uint64
	DeCommitTotalFreeThreshold    uint64
	LockPrefixTable               uint64
	MaximumAllocationSize         uint64
	VirtualMemoryThreshold        uint64
	ProcessAffinityMask           uint64
	ProcessHeapFlags              uint32
	CSDVersion                    uint16
	Reserved1                     uint16
	EditList                      uint64
	SecurityCookie                uint64
	SEHandlerTable                uint64
	SEHandlerCount                uint64
	GuardCFCheckFunctionPointer   uint64
	Reserved2                     uint64
	GuardCFFunctionTable          uint64
	GuardCFFunctionCount          uint64
	GuardFlags                    uint32
}

// BoundImportDescriptorD raw field data read from file
type BoundImportDescriptorD struct {
	TimeDateStamp               uint32
	OffsetModuleName            uint16
	NumberOfModuleForwarderRefs uint16
}

// BoundImportDescriptor wrapper
type BoundImportDescriptor struct {
	Data       BoundImportDescriptorD
	FileOffset uint32
	Size       uint32
}

func newBoundImportDescriptor(fileOffset uint32) (header *BoundImportDescriptor) {
	header = new(BoundImportDescriptor)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (bid *BoundImportDescriptor) String() string {
	return sectionString(bid.FileOffset, "BoundImportDescriptor", bid.Data)
}

// BoundForwarderRefD raw field data from file
type BoundForwarderRefD struct {
	TimeDateStamp    uint32
	OffsetModuleName uint16
	Reserved         uint16
}

// BoundForwarderRef wrapper
type BoundForwarderRef struct {
	Data       BoundForwarderRefD
	FileOffset uint32
	Size       uint32
}

func newBoundForwarderRef(fileOffset uint32) (header *BoundForwarderRef) {
	header = new(BoundForwarderRef)
	header.Size = uint32(binary.Size(header.Data))
	header.FileOffset = fileOffset
	return header
}

func (bfr *BoundForwarderRef) String() string {
	return sectionString(bfr.FileOffset, "BoundForwarderRef", bfr.Data)
}

/* Helper functions */

func sectionString(fileOffset uint32, sectionName string, iface interface{}) string {
	sType := reflect.TypeOf(iface)
	sValue := reflect.ValueOf(iface)
	values := "[" + sectionName + "]\n"
	for i := 0; i < sType.NumField(); i++ {
		sField := sType.Field(i)
		vField := sValue.Field(i)
		kind := vField.Kind()

		fieldOffset := uint64(fileOffset) + uint64(sField.Offset)
		if kind == reflect.Uint8 || kind == reflect.Uint16 || kind == reflect.Uint32 {
			values += fmt.Sprintf("0x%-4X\t\t0x%-4X\t%-24s\t0x%X"+
				"\n", fieldOffset, sField.Offset, sField.Name, vField.Interface())
		}

		if sValue.Kind() == reflect.Array {
			elemType := sValue.Type().Elem().Kind()
			if elemType == reflect.Struct || elemType == reflect.Ptr || elemType == reflect.Map || elemType == reflect.Func || elemType == reflect.Interface {
				continue
			}

		}
		if kind == reflect.Array || kind == reflect.Slice || kind == reflect.String {
			values += fmt.Sprintf("0x%-4X\t\t0x%-4X\t%-24s\t%s"+
				"\n", fieldOffset, sField.Offset, sField.Name, vField.Interface())
		}

		if kind == reflect.Bool {
			values += fmt.Sprintf("0x%-4X\t\t0x%-4X\t%-24s\t%t"+
				"\n", fieldOffset, sField.Offset, sField.Name, vField.Interface())
		}
	}
	return values
}

func flagString(flagMap map[string]bool) string {
	if len(flagMap) == 0 {
		return "No Flags\n"
	}
	values := "Flags:\n"
	for key, value := range flagMap {
		values += fmt.Sprintf("%-40s\t%t\n", key, value)
	}
	return values
}

// FIXME: this is really just checking for zero-values, could just be
// replaced with == thing{}?
func emptyStruct(iface interface{}) bool {
	value := reflect.ValueOf(iface)
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		kind := field.Kind()
		if kind == reflect.Uint8 && field.Interface().(uint8) != uint8(0) {
			return false
		}
		if kind == reflect.Uint16 && field.Interface().(uint16) != uint16(0) {
			return false
		}
		if kind == reflect.Uint32 && field.Interface().(uint32) != uint32(0) {
			return false
		}
		if kind == reflect.Uint64 && field.Interface().(uint64) != uint64(0) {
			return false
		}
		if kind == reflect.Array && len(field.Interface().([]byte)) != 0 {
			return false
		}
		if kind == reflect.String && len(field.Interface().(string)) != 0 {
			return false
		}
	}
	return true
}

// SetFlags takes the binary flag value read from the guest, checks it against
// all the key-values in charMap, and sets the corresponding values in the
// passed in flagMap
//
// Should be called after reading raw header data out of the file to fill in
// convience structs
func SetFlags(flagMap map[string]bool, charMap map[string]uint32, characteristic uint32) {
	for key, value := range charMap {
		if characteristic&value != 0x0 {
			flagMap[key] = true
		} else {
			flagMap[key] = false
		}
	}
}
