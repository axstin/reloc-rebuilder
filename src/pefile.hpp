#pragma once

//#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <cassert>
#include <memory>

#include "nt.hpp"
#include "util.hpp"

using handle_t = void *;

struct pe_appended_section
{
    pe::image_section_header *header = nullptr;
    std::string contents {};
};

class pe_file
{
public:
    enum class alignment : unsigned char
    {
        file,
        section
    };

    pe_file(const char *filename) { open(filename); }
    pe_file() {}

    bool open(const char *filename);
    void close(const char *error);
    void build();
    bool write(const char *output_file_name);

    bool is_open() const { return region.valid(); }
    const char *get_file_name() const { return file_name; } 

    bool is_64bit() const
    {
        return is_x64;
    }

    pe::dos_header *get_dos_header() const
    {
        return dos_header;
    }

    pe::image_header_32 *get_nt_headers32() const
    {
        assert(!is_x64);
        return &nt_headers->x86;
    }

    pe::image_header_64 *get_nt_headers64() const
    {
        assert(is_x64);
        return &nt_headers->x64;
    }

    pe::data_directory *get_directory_entry(pe::directory_id id)
    {
        return static_cast<int>(id) < directories.size() ? &directories[static_cast<int>(id)] : nullptr;
    }

    uint64_t get_image_base() const
    {
        return is_x64 ? nt_headers->x64.optional_header.image_base : nt_headers->x86.optional_header.image_base;
    }

    util::array_view<pe::image_section_header> get_sections() const
    {
        return section_headers;
    }

    size_t align(size_t value, alignment align = alignment::file) const
    {
        size_t factor = align == alignment::file ? file_alignment : section_alignment;
        return ALIGN_UP(value, factor);
    }

    pe_appended_section *add_section(const char *name)
    {
        if (new_sections.size() >= free_section_headers.size()) return nullptr;
        auto new_section = std::make_unique<pe_appended_section>();
        new_section->header = &free_section_headers[new_sections.size()];
        memcpy(new_section->header->name, name, sizeof(new_section->header->name));
        auto *result = new_section.get();
        new_sections.push_back(std::move(new_section));
        return result;
    }

    const util::memory_region &memory() const
    {
        return region;
    }

    const char *last_error = nullptr;
private:

    void validate_header();
    void load_free_section_headers();
    size_t calculate_size_of_headers();

    handle_t file = (handle_t)-1;
    handle_t mapping = NULL;

    util::memory_region region;
    bool is_x64 {};
    pe::dos_header *dos_header = nullptr;
    pe::image_header_union *nt_headers = nullptr;
    util::array_view<pe::data_directory> directories {};
    util::array_view<pe::image_section_header> section_headers {};
    util::array_view<pe::image_section_header> free_section_headers {};
    uint32_t file_alignment {};
    uint32_t section_alignment {};

    const char *file_name = nullptr;
    std::vector<std::unique_ptr<pe_appended_section>> new_sections;	
};