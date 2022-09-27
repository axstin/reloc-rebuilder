#include <Windows.h>
#include "pefile.hpp"

#include <fstream>

uint64_t get_file_size(handle_t file)
{
    DWORD high;
    DWORD low = GetFileSize(file, &high);
    return (uint64_t)high << 32 | low;
}

bool pe_file::open(const char *filename)
{
    if (is_open())
    {
        last_error = "already open";
        return false;
    }

    file_name = filename;

    file = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        close("unable to open file");
        return false; 
    }

    mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping)
    {
        close("unable to create mapping");
        return false;
    }

    void *base = MapViewOfFile(mapping, FILE_MAP_COPY, 0, 0, 0);
    if (!base)
    {
        close("unable to map view of file");
        return false;
    }

    region.reset(base, get_file_size(file));

    validate_header();
    if (is_open()) load_free_section_headers();

    return is_open();
}

void pe_file::validate_header()
{
    dos_header = region.at<pe::dos_header>(0);
    if (!dos_header || dos_header->e_magic != pe::dos_signature)
    {
        close("invalid pe file (bad dos header)");
        return;
    }

    nt_headers = region.at<pe::image_header_union>(dos_header->e_lfanew);
    if (!nt_headers || nt_headers->all.signature != pe::image_signature)
    {
        close("invalid pe file (bad nt header)");
        return;
    }

    is_x64 = nt_headers->x86.optional_header.magic == pe::optional_header_magic::PE64;

    if (is_x64)
    {
        directories = { nt_headers->x64.optional_header.data_directory, nt_headers->x64.optional_header.number_of_rva_and_sizes };
        file_alignment = nt_headers->x64.optional_header.file_alignment;
        section_alignment = nt_headers->x64.optional_header.section_alignment;
    }
    else
    {
        directories = { nt_headers->x86.optional_header.data_directory, nt_headers->x86.optional_header.number_of_rva_and_sizes };
        file_alignment = nt_headers->x86.optional_header.file_alignment;
        section_alignment = nt_headers->x86.optional_header.section_alignment;
    }

    section_headers = region.array_at<pe::image_section_header>(
        dos_header->e_lfanew + sizeof(pe::image_file_header) + nt_headers->all.file_header.size_of_optional_header, nt_headers->all.file_header.number_of_sections);

    if (!directories || !section_headers || section_headers.empty())
    {
        close("invalid pe file (bad file header)");
        return;
    }
}

void pe_file::load_free_section_headers()
{
    assert(section_headers);

    pe::image_section_header *closest_section = &section_headers[0];
    for (int i = 1; i < section_headers.size(); i++)
    {
        auto *header = &section_headers[i];
        if (header->pointer_to_raw_data > 0 && header->pointer_to_raw_data < closest_section->pointer_to_raw_data)
        {
            closest_section = header;
        }
    }

    size_t section_headers_offset = dos_header->e_lfanew + sizeof(pe::image_file_header) + nt_headers->all.file_header.size_of_optional_header;
    size_t free_section_headers_offset = section_headers_offset + section_headers.size() * sizeof(pe::image_section_header);

    if (closest_section->pointer_to_raw_data < free_section_headers_offset)
    {
        close("invalid pe file (corrupt section header)");
        return;
    }

    size_t num_free_section_headers = (closest_section->pointer_to_raw_data - free_section_headers_offset) / sizeof(pe::image_section_header);
    if (num_free_section_headers == 0)
    {
        close("invalid pe file (no free sections)");
        return;
    }

    free_section_headers = region.array_at<pe::image_section_header>(free_section_headers_offset, num_free_section_headers);
}

size_t pe_file::calculate_size_of_headers()
{
    return dos_header->e_lfanew + sizeof(pe::image_file_header) + nt_headers->all.file_header.size_of_optional_header + nt_headers->all.file_header.number_of_sections * sizeof(pe::image_section_header);
}

void pe_file::build()
{
    // update number of sections
    nt_headers->all.file_header.number_of_sections = section_headers.size() + new_sections.size();

    // check size of headers
    size_t size_of_headers = align(calculate_size_of_headers(), alignment::file);
    uint32_t *p_size_of_headers = is_x64 ? &nt_headers->x64.optional_header.size_of_headers : &nt_headers->x86.optional_header.size_of_headers;
    
    // "The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment."
    // this shouldn't change... show warning or raise exception?
    if (size_of_headers != *p_size_of_headers)
    {
        printf("WARNING: calculated SizeOfHeaders (%zx) != existing value (%x)\n", size_of_headers, *p_size_of_headers);
        *p_size_of_headers = size_of_headers;
    }
    
    // find farthest section in virtual address space
    auto *farthest_section = &section_headers[0];
    for (int i = 1; i < section_headers.size(); i++)
    {
        auto *section = &section_headers[i];
        if (section->end_va() > farthest_section->end_va()) farthest_section = section;
    }

    // update new section headers
    uint32_t va = align(farthest_section->end_va(), alignment::section);
    uint32_t fo = align(region.size(), alignment::file);

    for (auto &section : new_sections)
    {
        section->header->virtual_address = va;
        section->header->virtual_size = align(section->contents.size(), alignment::section);
        va += section->header->virtual_size;

        section->header->pointer_to_raw_data = fo;
        section->header->size_of_raw_data = align(section->contents.size(), alignment::file);
        fo += section->header->size_of_raw_data;
    }

    // update size of image
    uint32_t *p_size_of_image = is_x64 ? &nt_headers->x64.optional_header.size_of_image : &nt_headers->x86.optional_header.size_of_image;
    if (va < *p_size_of_image) printf("WARNING: calculated SizeOfImage (%x) is smaller than existing value (%x)\n", va, *p_size_of_image);
    *p_size_of_image = va;
}

std::string padding(int size)
{
    return size > 0 ? std::string(size, '\0') : "";
}

bool pe_file::write(const char *output_file_name)
{
    // assumes build() called

    std::fstream file(output_file_name, std::ios::binary | std::ios::out);
    if (!file.is_open())
    {
        return false;
    }

    // write the existing file
    file.write((const char *)region.get(), region.size());

    // write new sections
    uint32_t fo = align(region.size(), alignment::file);
    file << padding(fo - region.size());
    for (auto &section : new_sections)
    {
        file << section->contents;
        file << padding(section->header->size_of_raw_data - section->contents.size());
    }

    return true;
}

void pe_file::close(const char *error)
{
    if (region) { UnmapViewOfFile(region.get()); region.reset(); }
    if (mapping) CloseHandle(mapping);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (error) last_error = error;
}