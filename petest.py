#!/usr/bin/env python
import sys
import pefile
from pprint import pprint
import ordlookup

def ProcessFile(filename):
    pe_report = {}
    pe = pefile.PE(filename)

    print pe.DOS_HEADER
    #pprint(pe.DOS_HEADER.__dict__)
    print pe.NT_HEADERS
    #pprint(pe.NT_HEADERS.__dict__)
    print pe.FILE_HEADER
    #pprint(pe.FILE_HEADER.__dict__)
    
    print pe.OPTIONAL_HEADER
    #pprint(pe.OPTIONAL_HEADER.__dict__)
    pprint(pe.OPTIONAL_HEADER.DATA_DIRECTORY)

    print '\nSections\n'
    for section in pe.sections:
        print section 
        #pprint(section.__dict__)

    #for entry in  pe.DIRECTORY_ENTRY_IMPORT:
    #    print entry.struct
    #    for imp in entry.imports:
    #        print '\nImport Data:'
    #        for key, val in imp.__dict__.items():
    #            if type(val) == int:
    #                print "%-20s\t\t0x%x" % (key, val)
    #            if type(val) in (str, unicode, type(None)):
    #                print "%-20s\t\t%s" % (key, val)

    print '\nDIRECTORY_ENTRY_IMPORT\n'
    if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                funcname = None
                if not imp.name:
                    funcname = ordlookup.ordLookup(entry.dll, imp.ordinal, make_name=True)
                    if not funcname:
                        funcname = str(imp.ordinal)
                else:
                    funcname = imp.name

                if not funcname:
                    continue 
                print funcname


    


    print '\nDIRECTORY_ENTRY_EXPORT\n'
    print pe.DIRECTORY_ENTRY_EXPORT.struct
    
    
    if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print exp.name

    return 

    print '\nDIRECTORY_ENTRY_RESOURCE\n'
    
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.id != None:
                print 'id: %s' % str(resource_type.id)
                if (hasattr(resource_type, 'directory')):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resources in resource_id.directory.entries:
                                # Get all languages
                                print str(resources.id)                                
                                data = pe.get_data(resources.data.struct.OffsetToData, resources.data.struct.Size)
                                print " ".join("{:02x}".format(ord(c)) for c in data[:5])


if __name__ == '__main__':
    assert len(sys.argv) == 2, "Usage: python petest <filename>"
    filename = sys.argv[1]

    ProcessFile(filename)

