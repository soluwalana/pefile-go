package main

import (
	"fmt"
	"log"
	"os"

	"github.com/awsaba/pefile-go"
)

func main() {
	log.Println("hello everyone, lets parse your PEFile")
	args := os.Args[1:]
	if len(args) == 0 {
		log.Println("Must specify the filename of the PEFile")
		return
	}
	pefile, err := pefile.NewPEFile(args[0])
	if err != nil {
		log.Println("Ooopss looks like there was a problem")
		log.Println(err)
		return
	}
	log.Println(pefile.Filename)
	log.Println(pefile.DosHeader)
	log.Println(pefile.NTHeader)
	log.Println(pefile.FileHeader)
	log.Println(pefile.OptionalHeader)

	for key, val := range pefile.OptionalHeader.DataDirs {
		log.Println(key)
		log.Println(val)
	}

	for _, s := range pefile.Sections {
		log.Println(s.String())
	}

	/*for _, val := range pefile.ImportDescriptors {
		log.Println(val)
		for _, val2 := range val.Imports {
			log.Println(val2)
		}
	}*/

	log.Println("\nDIRECTORY_ENTRY_IMPORT\n")
	for _, entry := range pefile.ImportDescriptors {
		for _, imp := range entry.Imports {
			var funcname string
			if len(imp.Name) == 0 {
				funcname = fmt.Sprintf("ordinal+%d", imp.Ordinal)
			} else {
				funcname = string(imp.Name)
			}
			log.Println(funcname)
		}
	}

	log.Println("\nDIRECTORY_ENTRY_EXPORT\n")
	log.Println(pefile.ExportDirectory)
	for _, entry := range pefile.ExportDirectory.Exports {
		log.Println(string(entry.Name))
	}

}
