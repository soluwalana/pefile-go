# pefile-go

Golang implementation of [pefile](https://github.com/erocarrera/pefile/), stripped down to some bare
minimums.

To use as a library:

```
  $ go get github.com/awsaba/pefile-go
```

To install the demo program stub:

```
  $ go install github.com/awsaba/pefile-go/pefile
```

## Features

Some of the tasks that _pefile_ makes possible are:

  * Inspecting headers
  * Analysis of sections' data
  * Parsing exports

## Motivations

  * Have a golang library for PE file related utilities.
  * Projects based on "debug/pefile" would have an awkward split between was it
    added on by the wrapper lib and what is included in the core go lib.

## Dependencies

pefile-go is self-contained. It has no dependecies and currently assumes a
little-endian architecture.

## Acknowledgements

  * The original [pefile](https://github.com/erocarrera/pefile/)
  * Sam Oluwalana's original go port of [pefile-go](https://github.com/soluwalana/pefile-go/)

## Major changes from those versions

  * No hard-coded lists of ordinals.  They were not accurate to those files in
    recent versions of Windows.  If you need them, Microsoft tools can be
    used to retrieve the public symbols that contains that information, but that
    is beyond the scope of this project.
  * Simpler package layout.
  * As much adherence to golang conventions as possible.  Hopefully what's left
    can be configured to be ignored by your editor of choice when running
    golint.

## Additional resources (originally from pefile's readme)

PDFs of posters depicting the PE file format:

  * [Portable Executable Format](https://docs.google.com/open?id=0B3_wGJkuWLytbnIxY1J5WUs4MEk) shows the full view of the headers and structures defined by the Portable Executable format
  * [Portable Executable Format. A File Walkthrough](https://docs.google.com/open?id=0B3_wGJkuWLytQmc2di0wajB1Xzg) Shows a walkthrough over the raw view of an executable file with the PE format fields laid out over the corresponding areas

The following links provide detailed information about the PE format and its structures.

  * [corkami's wiki page about the PE format](https://code.google.com/p/corkami/wiki/PE) has grown to be one of the most in-depth repositories of information about the PE format
  * [An In-Depth Look into the Win32 Portable Executable File Format](http://msdn.microsoft.com/msdnmag/issues/02/02/PE/default.aspx)
  * [An In-Depth Look into the Win32 Portable Executable File Format, Part 2](http://msdn.microsoft.com/msdnmag/issues/02/03/PE2/default.aspx)
  * [The Portable Executable File Format](http://www.csn.ul.ie/~caolan/publink/winresdump/winresdump/doc/pefile.html)
  * [Get icons from Exe or DLL the PE way](http://www.codeproject.com/cpp/GetIconsfromExeorDLLs.asp)
  * Solar Eclipse's Tiny PE page at "http://www.phreedom.org/solar/code/tinype/" is no longer available, corkami has a copy of TinyPE [here](https://code.google.com/p/corkami/source/browse/trunk/misc/MakePE/examples/PE/tinype.asm?r=179)
