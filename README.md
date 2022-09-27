# reloc-rebuilder

`reloc-rebuilder` is a tool for rebuilding or constructing [relocation data](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only) from differently-based dumps of a Windows x86/x64 executable. Inspired by [ReloX](http://web.archive.org/web/20091030072027/http://www.woodmann.com/collaborative/tools/index.php/ReloX).

## Usage

```
usage: reloc-rebuilder [options] pe_file1 pe_file2 ...
    Construct a .reloc section from differently-based PE (Portable Executable) images. Each image should have at least one section with
    matching Name, SizeOfRawData, and VirtualSize fields. Unless --raw is specified, the output file is a copy of the first provided
    image with the new .reloc section appended.

    options:
        -h, --help              print usage
        -o, --output filename   the output file name (default: "rr-output.bin")
        -r, --raw               specifies raw section output
```

