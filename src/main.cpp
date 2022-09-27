// Austin J 2018
// Refactored in 2022

#include <cstdio>
#include <vector>
#include <unordered_map>
#include <map>
#include <set>
#include <memory>
#include <fstream>

#include "pefile.hpp"
#include "nt.hpp"

const char *const usage =
"usage: reloc-rebuilder [options] pe_file1 pe_file2 ...\n"
"    Construct a .reloc section from differently-based PE (Portable Executable) images. Each image should have at least one section with\n"
"    matching Name, SizeOfRawData, and VirtualSize fields. Unless --raw is specified, the output file is a copy of the first provided\n"
"    image with the new .reloc section appended.\n\n"
"    options:\n"
"        -h, --help              print usage\n"
"        -o, --output filename   the output file name (default: \"rr-output.bin\")\n"
"        -r, --raw               specifies raw section output\n";

char *arg_output = nullptr;
char *arg_section = nullptr;
bool arg_raw = false;

using similar_sections_t = std::vector<struct rr_section>;

std::vector<std::unique_ptr<pe_file>> files;
std::vector<similar_sections_t> ss_containers; /* a 3d array of similar sections. rows = similar sections, columns = sections belonging to a pe_file */
int base_file_column = -1; 
std::map<size_t, std::vector<uint16_t>> reloc_blocks;
size_t reloc_count = 0;

struct rr_section
{
    pe::image_section_header *header {};
    uint64_t image_base = 0;
    const uint8_t *contents {};

    template <typename I>
    bool read_rva(size_t offset, pe::rva_t &out) const
    {
        uint64_t value = *(I *)(contents + offset);
        if (value < image_base) return false;
        value -= image_base;
        if (value >= ULONG_MAX) return false;
        out = value;
        return true;
    }
};

void find_similar_sections()
{
    struct section_comparer
    {
        bool operator()(pe::image_section_header *a, pe::image_section_header *b) const
        {
            if (a->size_of_raw_data != b->size_of_raw_data) return a->size_of_raw_data < b->size_of_raw_data;
            if (a->virtual_size != b->virtual_size) return a->virtual_size < b->virtual_size;
            return memcmp(a->name, b->name, 8) < 0;
        }
    };

    std::map<pe::image_section_header *, std::map<pe_file *, pe::image_section_header *>, section_comparer> lookup;

    /* group together similar sections */
    for (auto &file : files)
        for (auto &section : file->get_sections())
            lookup[&section][file.get()] = &section;

    /* record sections that can be found in all input files */
    for (auto& p1 : lookup)
    {
        if (p1.second.size() == files.size())
        {
            similar_sections_t container {};

            for (auto& p2 : p1.second)
            {
                auto *header = p2.second;
                if (const auto *data = p2.first->memory().at<uint8_t>(header->pointer_to_raw_data, header->size_of_raw_data))
                {
                    if (base_file_column == -1 && p2.first == files[0].get())
                        base_file_column = container.size(); 
                    container.push_back({ header, p2.first->get_image_base(), data });
                }
                else
                {
                    break;
                }
            }

            if (container.size() == files.size())
                ss_containers.push_back(std::move(container));
        }
    }
}

template <typename uint_type>
void find_relocations(size_t index)
{
    auto& container = ss_containers[index];
    auto& first_section = container[0];
    size_t offset = 0;
    size_t count = 0;

    printf("[-] scanning %s...", first_section.header->name);

    if (first_section.header->size_of_raw_data >= sizeof(uint_type))
    {
        for (uint32_t offset = 0; offset <= first_section.header->size_of_raw_data - sizeof(uint_type); offset++)
        {
            pe::rva_t rva;
            if (first_section.read_rva<uint_type>(offset, rva))
            {
                bool match = true;

                for (int i = 1; i < container.size(); i++)
                {
                    pe::rva_t tmp;
                    if (!container[i].read_rva<uint_type>(offset, tmp) || tmp != rva)
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                {
                    uint64_t reloc_rva = offset + container[base_file_column].header->virtual_address;
                    if (reloc_rva <= UINT_MAX)
                    {
                        if constexpr (std::is_same_v<uint_type, uint64_t>)
                        {
                            reloc_blocks[reloc_rva / 4096].push_back((static_cast<uint16_t>(pe::image_relocation_type::DIR64) << 12) | (reloc_rva % 4096));
                        }
                        else
                        {
                            reloc_blocks[reloc_rva / 4096].push_back((static_cast<uint16_t>(pe::image_relocation_type::HIGH_LOW) << 12) | (reloc_rva % 4096));
                        }

                        reloc_count++;
                        count++;
                        offset += sizeof(uint_type) - 1;
                    }
                    else
                    {
                        // well that ain't right
                    }
                }
            }
        }
    }

    printf(" %zu relocations found\n", count);
}

std::string generate_reloc_section()
{
    std::string out;

    size_t predicted_size = 0;
    for (auto &block : reloc_blocks)
        predicted_size += pe::image_relocation_block::calc_size_bytes(block.second.size());

    out.clear();
    out.reserve(predicted_size);

    for (auto& block : reloc_blocks)
    {
        pe::image_relocation_block_header header;

        header.base_rva = block.first * 4096;
        header.set_num_entries(block.second.size());

#ifndef NDEBUG
        size_t buffer_size = out.size();
#endif

        size_t entries_size = block.second.size() * sizeof(pe::image_relocation_entry);
        size_t unaligned_block_size = sizeof(header) + entries_size;

        out.append((const char *)&header, sizeof(header));
        out.append((const char *)block.second.data(), entries_size);
        out.resize(out.size() + (header.size_bytes - unaligned_block_size)); // "The base relocation table is divided into blocks. Each block represents the base relocations for a 4K page. Each block must start on a 32-bit boundary."		
        
        assert(out.size() - buffer_size == header.size_bytes);
    }

    assert(out.size() == predicted_size);

    return out;
}

void start()
{
    if (files.size() < 2)
    {
        printf("ERROR: at least two pe files must be provided\n");
        return;
    }

    pe_file *base_file = files[0].get();
    bool is_x64 = base_file->is_64bit();

    printf("\n[-] finding similar sections... ");
    find_similar_sections();
    printf("%zu found\n", ss_containers.size());

    if (is_x64)
    {
        for (int i = 0; i < ss_containers.size(); i++)
        {
            find_relocations<uint64_t>(i);
        }
    }
    else
    {
        for (int i = 0; i < ss_containers.size(); i++)
        {
            find_relocations<uint32_t>(i);
        }
    }

    printf("\n[-] total relocations: %zu\n", reloc_count);
    printf("[-] total relocation blocks: %zu\n", reloc_blocks.size());
    printf("[-] generating section based on %s...\n", base_file->get_file_name());

    std::string reloc_section_data = generate_reloc_section();
    const char *output_file_name = arg_output ? arg_output : "rr-output.bin";

    if (arg_raw)
    {
        printf("[-] saving section data to %s...\n", output_file_name);

        std::fstream file(output_file_name, std::ios::binary | std::ios::out);
        if (!file.is_open())
        {
            printf("ERROR: failed to open output file\n");
            return;
        }

        file << reloc_section_data;
    }
    else
    {
        printf("[-] saving new image to %s...\n", output_file_name);

        // add section
        auto *section = base_file->add_section(arg_section ? arg_section : ".reloc");
        if (!section)
        {
            printf("ERROR: base file does not have room for a new section\n");
            return;
        }
        section->header->characteristics = pe::image_section_flags::MEM_READ | pe::image_section_flags::MEM_DISCARDABLE | pe::image_section_flags::CNT_INITIALIZED_DATA;
        section->contents = reloc_section_data;

        // build
        base_file->build();

        // update relocations data directory
        auto *directory_entry = base_file->get_directory_entry(pe::directory_id::RELOCATIONS);
        if (!directory_entry)
        {
            printf("ERROR: base file does not have relocations directory\n");
            return;
        }
        directory_entry->virtual_address = section->header->virtual_address;
        directory_entry->size = section->header->virtual_size;

        if (!base_file->write(output_file_name))
        {
            printf("ERROR: failed to open output file\n");
            return;
        }
    }

    printf("[-] done!\n");
}

bool parse_int(const char *input, size_t& out)
{
    try
    {
        out = strlen(input) > 2 && input[0] == '0' && input[1] == 'x' ? std::stoi(input + 2, nullptr, 16) : std::stoi(input);
        return true;
    }
    catch (std::exception&)
    {
        return false;
    }
}

int main(int argc, char *argv[])
{
    printf(".reloc rebuilder v1.0.0 - Austin J 2022\nhttps://github.com/axstin/reloc-rebuilder\n\n");

    if (argc <= 1)
    {
        printf("%s\n", usage);
        return 0;
    }

    std::set<uint64_t> bases;
    bool map_files = false;

    for (int i = 1; i < argc; i++)
    {
#define IF_OPT(s, l) if (strcmp(argv[i], s) == 0 || strcmp(argv[i], l) == 0)
        IF_OPT("-h", "--help")
        {
            printf("%s\n", usage);
            return 0;
        }
        IF_OPT("-o", "--output")
        {
            arg_output = ++i < argc ? argv[i] : nullptr;
            continue;
        }
        IF_OPT("-r", "--raw")
        {
            arg_raw = true;
            continue;
        }
        IF_OPT("-s", "--section")
        {
            arg_section = ++i < argc ? argv[i] : nullptr;
            if (arg_section) arg_section = strlen(arg_section) <= 8 ? arg_section : nullptr;
            continue;
        }  
#undef IF_OPT

        auto file = std::make_unique<pe_file>(argv[i]);
        if (!file->is_open())
        {
            printf("ERROR: failed to open file %s (%s)\n", argv[i], file->last_error);
            return 0;
        }

        printf("[-] loaded %s @ 0x%p (%zu bytes, %s, base 0x%llx)\n", argv[i], file->memory().get(), file->memory().size(), file->is_64bit() ? "64-bit" : "32-bit", file->get_image_base());

        if (!files.empty() && file->is_64bit() != files[0]->is_64bit())
        {
            printf("ERROR: input files have mismatched bitness\n");
            return 0;
        }

        if (!bases.insert(file->get_image_base()).second)
        {
            printf("ERROR: input files must have differing image bases\n");
            return 0;
        }

        files.push_back(std::move(file));
    }

    start();
}