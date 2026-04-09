#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string_view>
#include <vector>

#include "rothalyx/analysis/program_analysis.hpp"
#include "rothalyx/memory/address_space.hpp"

namespace {

bool has_typed_prefix(
    const rothalyx::type::FunctionTypes& types,
    const std::string_view prefix,
    const rothalyx::ir::ScalarType expected_type
) {
    return std::any_of(
        types.variables.begin(),
        types.variables.end(),
        [&](const rothalyx::type::RecoveredVariable& variable) {
            return std::string_view(variable.name).rfind(prefix, 0) == 0 && variable.type == expected_type;
        }
    );
}

}  // namespace

int main() {
    constexpr std::uint64_t kCodeBase = 0x1000;
    constexpr std::uint64_t kDataBase = 0x1020;

    const std::array<std::uint8_t, 27> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x48, 0x8D, 0x3D, 0x15, 0x00, 0x00, 0x00,
        0x74, 0x05,
        0xE8, 0x03, 0x00, 0x00, 0x00,
        0x31, 0xC0,
        0xC3,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };

    const std::array<std::uint8_t, 6> data_bytes{
        0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00,
    };

    rothalyx::memory::AddressSpace address_space;
    if (!address_space.map_segment(
            rothalyx::memory::Segment{
                .name = ".text",
                .base_address = kCodeBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(code_bytes.data()),
                    reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())
                ),
                .permissions =
                    rothalyx::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = true,
                    },
            }
        ) ||
        !address_space.map_segment(
            rothalyx::memory::Segment{
                .name = ".rodata",
                .base_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .permissions =
                    rothalyx::memory::Permissions{
                        .readable = true,
                        .writable = false,
                        .executable = false,
                    },
            }
        )) {
        std::cerr << "segment mapping failed\n";
        return 1;
    }

    const auto image = rothalyx::loader::BinaryImage::from_components(
        "synthetic.bin",
        rothalyx::loader::BinaryFormat::Raw,
        rothalyx::loader::Architecture::X86_64,
        kCodeBase,
        kCodeBase,
        {
            rothalyx::loader::Section{
                .name = ".text",
                .virtual_address = kCodeBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(code_bytes.data()),
                    reinterpret_cast<const std::byte*>(code_bytes.data() + code_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = true,
            },
            rothalyx::loader::Section{
                .name = ".rodata",
                .virtual_address = kDataBase,
                .bytes = std::vector<std::byte>(
                    reinterpret_cast<const std::byte*>(data_bytes.data()),
                    reinterpret_cast<const std::byte*>(data_bytes.data() + data_bytes.size())
                ),
                .readable = true,
                .writable = false,
                .executable = false,
            },
        }
    );

    const auto analysis = rothalyx::analysis::Analyzer::analyze(image, address_space);
    const auto function_it = std::find_if(
        analysis.functions.begin(),
        analysis.functions.end(),
        [](const rothalyx::analysis::DiscoveredFunction& function) { return function.entry_address == 0x1000; }
    );
    if (function_it == analysis.functions.end()) {
        std::cerr << "failed to find root function\n";
        return 2;
    }

    if (!has_typed_prefix(function_it->recovered_types, "rsp.", rothalyx::ir::ScalarType::Pointer)) {
        std::cerr << "expected pointer type for stack pointer SSA values\n";
        return 3;
    }

    if (!has_typed_prefix(function_it->recovered_types, "rdi.", rothalyx::ir::ScalarType::Pointer)) {
        std::cerr << "expected pointer type for LEA-derived rdi value\n";
        return 4;
    }

    if (!has_typed_prefix(function_it->recovered_types, "eax.", rothalyx::ir::ScalarType::I32)) {
        std::cerr << "expected i32 type for eax SSA values\n";
        return 5;
    }

    return 0;
}
