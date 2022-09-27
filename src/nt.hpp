#pragma once

#include <cstdint>
#include <string>

#define ALIGN_UP(x, y) (((x) + ((y) - 1)) & -(int)(y))
#define ALIGN_DOWN(x, y) ((x) & -(int)(y))

namespace pe
{
    constexpr uint16_t dos_signature = 0x5A4D; // "MZ"
    constexpr uint32_t image_signature = 0x4550; // "PE"
    constexpr uint32_t max_data_directory_entries = 16;

    using rva_t = uint32_t;

	struct dos_header
	{
		uint16_t e_magic = dos_signature;   // Magic number
		uint16_t e_cblp = 0x90;             // Bytes on last page of file
		uint16_t e_cp = 3;                  // Pages in file
		uint16_t e_crlc = 0;                // Relocations
		uint16_t e_cparhdr = 4;             // Size of header in paragraphs
		uint16_t e_minalloc = 0;            // Minimum extra paragraphs needed
		uint16_t e_maxalloc = 0xFFFF;       // Maximum extra paragraphs needed
		uint16_t e_ss = 0;                  // Initial (relative) SS value
		uint16_t e_sp = 0xB8;               // Initial SP value
		uint16_t e_csum = 0;                // Checksum
		uint16_t e_ip = 0;                  // Initial IP value
		uint16_t e_cs = 0;                  // Initial (relative) CS value
		uint16_t e_lfarlc = 0x40;           // File address of relocation table
		uint16_t e_ovno = 0;                // Overlay number
        uint16_t e_res[4] = { 0 };          // Reserved words
		uint16_t e_oemid = 0;		    	// OEM identifier (for e_oeminfo)
		uint16_t e_oeminfo = 0;             // OEM information; e_oemid specific
        uint16_t e_res2[10] = { 0 };        // Reserved words
		uint32_t e_lfanew = 0x80;		    // File address of new exe header
	};

	enum class machine_type : uint16_t
	{
		UNKNOWN = 0,
		I386 = 0x014c,  // Intel 386.
		R3000 = 0x0162,  // MIPS little-endian, 0x160 big-endian
		R4000 = 0x0166,  // MIPS little-endian
		R10000 = 0x0168,  // MIPS little-endian
		WCEMIPSV2 = 0x0169,  // MIPS little-endian WCE v2
		ALPHA = 0x0184,  // Alpha_AXP
		SH3 = 0x01a2,  // SH3 little-endian
		SH3DSP = 0x01a3,
		SH3E = 0x01a4,  // SH3E little-endian
		SH4 = 0x01a6,  // SH4 little-endian
		SH5 = 0x01a8,  // SH5
		ARM = 0x01c0,  // ARM Little-Endian
		THUMB = 0x01c2,  // ARM Thumb/Thumb-2 Little-Endian
		ARMNT = 0x01c4,  // ARM Thumb-2 Little-Endian
		AM33 = 0x01d3,
		POWERPC = 0x01f0,  // IBM PowerPC Little-Endian
		POWERPCFP = 0x01f1,
		IA64 = 0x0200,  // Intel 64
		MIPS16 = 0x0266,  // MIPS
		ALPHA64 = 0x0284,  // ALPHA64
		MIPSFPU = 0x0366,  // MIPS
		MIPSFPU16 = 0x0466,  // MIPS
		AXP64 = 0x0284,
		TRICORE = 0x0520,  // Infineon
		CEF = 0x0CEF,
		EBC = 0x0EBC,  // EFI Byte Code
		AMD64 = 0x8664,  // AMD64 (K8)
		M32R = 0x9041,  // M32R little-endian
		ARM64 = 0xAA64,  // ARM64 Little-Endian
		CEE = 0xC0EE
	};

    namespace characteristics
    {
        constexpr int RELOCS_STRIPPED = 0x0001; // Relocation info stripped from file.
        constexpr int EXECUTABLE_IMAGE = 0x0002; // File is executable  (i.e. no unresolved external references).
        constexpr int LINE_NUMS_STRIPPED = 0x0004; // Line nunbers stripped from file.
        constexpr int LOCAL_SYMS_STRIPPED = 0x0008; // Local symbols stripped from file.
        constexpr int AGGRESIVE_WS_TRIM = 0x0010; // Aggressively trim working set
        constexpr int LARGE_ADDRESS_AWARE = 0x0020; // App can handle >2gb addresses
        constexpr int BYTES_REVERSED_LO = 0x0080; // Bytes of machine word are reversed.
        constexpr int MACHINE_32BIT = 0x0100; // 32 bit word machine.
        constexpr int DEBUG_STRIPPED = 0x0200; // Debugging info stripped from file in .DBG file
        constexpr int REMOVABLE_RUN_FROM_SWAP = 0x0400; // If Image is on removable media, copy and run from the swap file.
        constexpr int NET_RUN_FROM_SWAP = 0x0800; // If Image is on Net, copy and run from the swap file.
        constexpr int SYSTEM = 0x1000; // System File.
        constexpr int DLL = 0x2000; // File is a DLL.
        constexpr int UP_SYSTEM_ONLY = 0x4000; // File should only be run on a UP machine
        constexpr int BYTES_REVERSED_HI = 0x8000; // Bytes of machine word are reversed.
    };

    enum class image_subsystem : uint16_t
    {
        UNKNOWN = 0,  // Unknown subsystem.
        NATIVE = 1,  // Image doesn't require a subsystem.
        WINDOWS_GUI = 2,  // Image runs in the Windows GUI subsystem.
        WINDOWS_CUI = 3,  // Image runs in the Windows character subsystem.
        OS2_CUI = 5,  // image runs in the OS/2 character subsystem.
        POSIX_CUI = 7,  // image runs in the Posix character subsystem.
        NATIVE_WINDOWS = 8,  // image is a native Win9x driver.
        WINDOWS_CE_GUI = 9,  // Image runs in the Windows CE subsystem.
        EFI_APPLICATION = 10,  //
        EFI_BOOT_SERVICE_DRIVER = 11,   //
        EFI_RUNTIME_DRIVER = 12,  //
        EFI_ROM = 13,
        XBOX = 14,
        WINDOWS_BOOT_APPLICATION = 16,
        XBOX_CODE_CATALOG = 17
    };

    enum class optional_header_magic : uint16_t
    {
        PE32 = 0x10b,
        PE64 = 0x20b,
        ROM = 0x107,
    };

    enum class architecture
    {
        x86, // 32-bit
        x64  // 64-bit
    };

    enum class directory_id
    {
        EXPORT = 0,
        IMPORT = 1,
        RESOURCE = 2,
        EXCEPTION = 3,
        SECURITY = 4,
        RELOCATIONS = 5,
        DEBUG = 6,
        ARCHITECTURE = 7,
        GLOBAL_PTR = 8,
        TLS = 9,
        LOAD_CONFIG = 10,
        BOUND_IMPORT = 11,
        IAT = 12,
        DELAY_IMPORT = 13,
        COM_DESCRIPTOR = 14
    };

    struct data_directory
	{
        uint32_t virtual_address = 0;
        uint32_t size = 0;
	};

    namespace image_section_flags
    {
        constexpr int TYPE_REG = 0x00000000; // Reserved.
        constexpr int TYPE_DSECT = 0x00000001; // Reserved.
        constexpr int TYPE_NOLOAD = 0x00000002; // Reserved.
        constexpr int TYPE_GROUP = 0x00000004; // Reserved.
        constexpr int TYPE_NO_PAD = 0x00000008; // Reserved.
        constexpr int TYPE_COPY = 0x00000010; // Reserved.
        constexpr int CNT_CODE = 0x00000020; // Section contains code.
        constexpr int CNT_INITIALIZED_DATA = 0x00000040; // Section contains initialized data.
        constexpr int CNT_UNINITIALIZED_DATA = 0x00000080; // Section contains uninitialized data.
        constexpr int LNK_OTHER = 0x00000100; // Reserved.
        constexpr int LNK_INFO = 0x00000200; // Section contains comments or some other type of information.
        constexpr int TYPE_OVER = 0x00000400; // Reserved.
        constexpr int LNK_REMOVE = 0x00000800; // Section contents will not become part of image.
        constexpr int LNK_COMDAT = 0x00001000; // Section contents comdat.
        constexpr int MEM_PROTECTED = 0x00004000;
        constexpr int NO_DEFER_SPEC_EXC = 0x00004000; // Reset speculative exceptions handling bits in the TLB entries for this section.
        constexpr int GPREL = 0x00008000; // Section content can be accessed relative to GP
        constexpr int MEM_FARDATA = 0x00008000;
        constexpr int MEM_SYSHEAP = 0x00010000;
        constexpr int MEM_PURGEABLE = 0x00020000;
        constexpr int MEM_16BIT = 0x00020000;
        constexpr int MEM_LOCKED = 0x00040000;
        constexpr int MEM_PRELOAD = 0x00080000;
        constexpr int ALIGN_1BYTES = 0x00100000; //
        constexpr int ALIGN_2BYTES = 0x00200000; //
        constexpr int ALIGN_4BYTES = 0x00300000; //
        constexpr int ALIGN_8BYTES = 0x00400000; //
        constexpr int ALIGN_16BYTES = 0x00500000; // Default alignment if no others are specified.
        constexpr int ALIGN_32BYTES = 0x00600000; //
        constexpr int ALIGN_64BYTES = 0x00700000; //
        constexpr int ALIGN_128BYTES = 0x00800000; //
        constexpr int ALIGN_256BYTES = 0x00900000; //
        constexpr int ALIGN_512BYTES = 0x00A00000; //
        constexpr int ALIGN_1024BYTES = 0x00B00000; //
        constexpr int ALIGN_2048BYTES = 0x00C00000; //
        constexpr int ALIGN_4096BYTES = 0x00D00000; //
        constexpr int ALIGN_8192BYTES = 0x00E00000; //
        constexpr int ALIGN_MASK = 0x00F00000;
        constexpr int LNK_NRELOC_OVFL = 0x01000000; // Section contains extended relocations.
        constexpr int MEM_DISCARDABLE = 0x02000000; // Section can be discarded.
        constexpr int MEM_NOT_CACHED = 0x04000000; // Section is not cachable.
        constexpr int MEM_NOT_PAGED = 0x08000000; // Section is not pageable.
        constexpr int MEM_SHARED = 0x10000000; // Section is shareable.
        constexpr int MEM_EXECUTE = 0x20000000; // Section is executable.
        constexpr int MEM_READ = 0x40000000; // Section is readable.
        constexpr int MEM_WRITE = 0x80000000; // Section is writeable.
    };

    // IMAGE_DLLCHARACTERISTICS_
    namespace image_characteristics
    {
        constexpr int HIGH_ENTROPY_VA = 0x0020; // Image can handle a high entropy 64-bit virtual address space.
        constexpr int DYNAMIC_BASE = 0x0040; // DLL can move.
        constexpr int FORCE_INTEGRITY = 0x0080; // Code Integrity Image
        constexpr int NX_COMPAT = 0x0100; // Image is NX compatible
        constexpr int NO_ISOLATION = 0x0200; // Image understands isolation and doesn't want it
        constexpr int NO_SEH = 0x0400; // Image does not use SEH.  No SE handler may reside in this image
        constexpr int NO_BIND = 0x0800; // Do not bind this image.
        constexpr int APPCONTAINER = 0x1000; // Image should execute in an AppContainer
        constexpr int WDM_DRIVER = 0x2000; // Driver uses WDM model
        constexpr int GUARD_CF = 0x4000; // Image supports Control Flow Guard.
        constexpr int TERMINAL_SERVER_AWARE = 0x8000;
    }

    template <architecture A>
    struct optional_header;

    template <>
    struct optional_header<architecture::x86>
    {
        optional_header_magic magic = optional_header_magic::PE32;
        uint8_t major_linker_version = 0;
        uint8_t minor_linker_version = 0;
        uint32_t size_of_code = 0;
        uint32_t size_of_initialized_data = 0;
        uint32_t size_of_uninitialized_data = 0;
        uint32_t address_of_entry_point = 0;
        uint32_t base_of_code = 0;
        uint32_t base_of_data = 0;

        uint32_t image_base = 0x400000;
        uint32_t section_alignment = 0x1000;
        uint32_t file_alignment = 0x200;
        uint16_t major_os_version = 6;
        uint16_t minor_os_version = 0;
        uint16_t major_image_version = 0;
        uint16_t minor_image_version = 0;
        uint16_t major_subsystem_version = 6;
        uint16_t minor_subsystem_version = 0;
        uint32_t win32_version_value = 0;
        uint32_t size_of_image = 0;
        uint32_t size_of_headers = 0;
        uint32_t checksum = 0;
        image_subsystem subsystem = image_subsystem::WINDOWS_CUI;
        uint16_t dll_characteristics;
        uint32_t size_of_stack_reserve = 0x100000;
        uint32_t size_of_stack_commit = 0x1000;
        uint32_t size_of_heap_reserve = 0x100000;
        uint32_t size_of_heap_commit = 0x1000;
        uint32_t loader_flags = 0;
        uint32_t number_of_rva_and_sizes = max_data_directory_entries;
        data_directory data_directory[max_data_directory_entries] {};
    };

    template <>
    struct optional_header<architecture::x64>
    {
        optional_header_magic magic = optional_header_magic::PE64;
        uint8_t major_linker_version = 0;
        uint8_t minor_linker_version = 0;
        uint32_t size_of_code = 0;
        uint32_t size_of_initialized_data = 0;
        uint32_t size_of_uninitialized_data = 0;
        uint32_t address_of_entry_point = 0;
        uint32_t base_of_code = 0;

        uint64_t image_base = 0x0000000140000000ULL;
        uint32_t section_alignment = 0x1000;
        uint32_t file_alignment = 0x200;
        uint16_t major_os_version = 6;
        uint16_t minor_os_version = 0;
        uint16_t major_image_version = 0;
        uint16_t minor_image_version = 0;
        uint16_t major_subsystem_version = 6;
        uint16_t minor_subsystem_version = 0;
        uint32_t win32_version_value = 0;
        uint32_t size_of_image = 0;
        uint32_t size_of_headers = 0;
        uint32_t checksum = 0;
        image_subsystem subsystem = image_subsystem::WINDOWS_CUI;
        uint16_t dll_characteristics = 0;
        uint64_t size_of_stack_reserve = 0x100000;
        uint64_t size_of_stack_commit = 0x1000;
        uint64_t size_of_heap_reserve = 0x100000;
        uint64_t size_of_heap_commit = 0x1000;
        uint32_t loader_flags = 0;
        uint32_t number_of_rva_and_sizes = max_data_directory_entries;
        data_directory data_directory[max_data_directory_entries];
    };

    using optional_header_32 = optional_header<architecture::x86>;
    using optional_header_64 = optional_header<architecture::x64>;

    union optional_header_union
    {
        optional_header_32 x86;
        optional_header_64 x64;

        optional_header_union()
        {}
    };

	struct file_header
	{
	    machine_type machine = machine_type::UNKNOWN;
	    uint16_t number_of_sections = 0;
	    uint32_t time_date_stamp = 0;
	    uint32_t pointer_to_symbol_table = 0;
	    uint32_t number_of_symbols = 0;
        uint16_t size_of_optional_header = 0;
        uint16_t characteristics = 0;
	};

    struct image_file_header {
        uint32_t signature = image_signature;
        file_header file_header {};
    };

    // IMAGE_NT_HEADERS
    template <architecture A>
    struct image_header
    {
        uint32_t signature = image_signature;
        file_header file_header;
        optional_header<A> optional_header;
    };

    using image_header_32 = image_header<architecture::x86>;
    using image_header_64 = image_header<architecture::x64>;

    union image_header_union
    {
        image_file_header all;
        image_header_32 x86;
        image_header_64 x64;
    };

    struct image_section_header
    {
        char name[8] = { 0 };
        uint32_t virtual_size = 0;
        uint32_t virtual_address = 0;
        uint32_t size_of_raw_data = 0;
        uint32_t pointer_to_raw_data = 0;
        uint32_t pointer_to_relocations = 0;
        uint32_t pointer_to_line_numbers = 0;
        uint16_t number_of_relocations = 0;
        uint16_t number_of_line_numbers = 0;
        uint32_t characteristics = 0; // image_section_flags

        uint32_t end_va() const { return virtual_address + virtual_size; }
    };

    // 5: Relocations Directory

    // IMAGE_REL_BASED_
    enum class image_relocation_type : uint16_t 
    {
        NONE = 0, // IMAGE_REL_BASED_ABSOLUTE
        HIGH = 1,
        LOW = 2,
        HIGH_LOW = 3,
        HIGH_ADJ = 4,

        MACHINE_SPECIFIC_5 = 5,
        MIPS_JMPADDR = 5,
        ARM_MOV32 = 5,
        RISCV_HIGH20 = 5,

        RESERVED = 6,

        MACHINE_SPECIFIC_7 = 7,
        THUMB_MOV32 = 7,
        RISCV_LOW12I = 7,

        MACHINE_SPECIFIC_8 = 8,
        RISCV_LOW12S = 8,
        LOONGARCH32_MARK_LA = 8,
        LOONGARCH64_MARK_LA = 8,

        MACHINE_SPECIFIC_9 = 9,
        MIPS_JMPADDR16 = 9,

        DIR64 = 10
    };

    struct image_relocation_entry
    {
        image_relocation_type type : 4;
        uint16_t offset : 12;
    };
    static_assert(sizeof(image_relocation_entry) == sizeof(uint16_t), "relocation_entry size mismatch");

    struct image_relocation_block_header
    {
        rva_t base_rva;
        uint32_t size_bytes;

        static constexpr size_t calc_size_bytes(size_t num) { return sizeof(image_relocation_block_header) + ALIGN_UP(num * sizeof(image_relocation_entry), sizeof(uint32_t)); }
        size_t num_entries() const { return (size_bytes - sizeof(image_relocation_block_header)) / sizeof(image_relocation_entry); }
        void set_num_entries(size_t num) { size_bytes = calc_size_bytes(num); }
    };

    // IMAGE_BASE_RELOCATION
    struct image_relocation_block : image_relocation_block_header
    {
        image_relocation_entry entries[1];   
    };
}
