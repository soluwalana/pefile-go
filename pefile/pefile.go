package main

import (
	"fmt"
	"os"

	"github.com/awsaba/pefile-go"
)

func main() {
	fmt.Println("hello everyone, lets parse your PEFile")
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println("Must specify the filename of the PEFile")
		os.Exit(-1)
	}
	pefile, err := pefile.NewPEFile(args[0])
	if err != nil {
		fmt.Println("Ooopss looks like there was a problem")
		fmt.Println(err)
		os.Exit(2)
	}

	fmt.Println(pefile.Filename)

	for _, e := range pefile.Errors {
		fmt.Println("Parser warning:", e)
	}

	fmt.Println(pefile.DosHeader.String())
	fmt.Println(pefile.NTHeader.String())
	fmt.Println(pefile.COFFFileHeader.String())
	fmt.Println(pefile.OptionalHeader)

	for key, val := range pefile.OptionalHeader.DataDirs {
		fmt.Println(key)
		fmt.Println(val)
	}

	for _, s := range pefile.Sections {
		fmt.Println(s.String())
	}

	/*for _, val := range pefile.ImportDescriptors {
		fmt.Println(val)
		for _, val2 := range val.Imports {
			fmt.Println(val2)
		}
	}*/

	fmt.Println("\nDIRECTORY_ENTRY_IMPORT\n")
	for _, entry := range pefile.ImportDescriptors {
		fmt.Println(string(entry.Dll))
		for _, imp := range entry.Imports {
			var funcname string
			if len(imp.Name) == 0 {
				funcname = fmt.Sprintf("ordinal+%d", imp.Ordinal)
			} else {
				funcname = string(imp.Name)
			}
			fmt.Println("\t", funcname)
		}
	}

	if pefile.ExportDirectory != nil {
		fmt.Println("\nDIRECTORY_ENTRY_EXPORT\n")
		fmt.Println(pefile.ExportDirectory)
		for _, entry := range pefile.ExportDirectory.Exports {
			fmt.Printf("%d: %s:0x%x, forward: %s\n", entry.Ordinal, string(entry.Name), entry.Address, entry.Forwarder)
		}
	}

}
