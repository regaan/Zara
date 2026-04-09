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

std::vector<std::byte> to_bytes(const std::vector<std::uint8_t>& values) {
    return std::vector<std::byte>(
        reinterpret_cast<const std::byte*>(values.data()),
        reinterpret_cast<const std::byte*>(values.data() + values.size())
    );
}

const rothalyx::type::RecoveredStruct* find_struct_prefix_local(
    const rothalyx::type::FunctionTypes& types,
    const std::string_view prefix
) {
    const auto it = std::find_if(
        types.structs.begin(),
        types.structs.end(),
        [&](const rothalyx::type::RecoveredStruct& recovered) {
            return std::string_view(recovered.owner_name).rfind(prefix, 0) == 0;
        }
    );
    return it == types.structs.end() ? nullptr : &(*it);
}

const rothalyx::type::RecoveredArray* find_array_prefix_local(
    const rothalyx::type::FunctionTypes& types,
    const std::string_view prefix
) {
    const auto it = std::find_if(
        types.arrays.begin(),
        types.arrays.end(),
        [&](const rothalyx::type::RecoveredArray& recovered) {
            return std::string_view(recovered.owner_name).rfind(prefix, 0) == 0;
        }
    );
    return it == types.arrays.end() ? nullptr : &(*it);
}

bool has_field_offset(const rothalyx::type::RecoveredStruct& recovered, const std::int64_t offset) {
    return std::any_of(
        recovered.fields.begin(),
        recovered.fields.end(),
        [&](const rothalyx::type::RecoveredStructField& field) { return field.offset == offset; }
    );
}

}  // namespace

int main() {
    constexpr std::uint64_t kTextBase = 0x1000;

    const std::vector<std::uint8_t> code_bytes{
        0x55,
        0x48, 0x89, 0xE5,
        0x8B, 0x47, 0x04,
        0x8B, 0x4F, 0x08,
        0x8B, 0x14, 0x86,
        0x89, 0x57, 0x0C,
        0x89, 0xD0,
        0xC9,
        0xC3,
    };

    rothalyx::memory::AddressSpace address_space;
    const auto image = rothalyx::loader::BinaryImage::from_components(
        "composite-type.bin",
        rothalyx::loader::BinaryFormat::Raw,
        rothalyx::loader::Architecture::X86_64,
        kTextBase,
        kTextBase,
        {
            rothalyx::loader::Section{
                .name = ".text",
                .virtual_address = kTextBase,
                .bytes = to_bytes(code_bytes),
                .readable = true,
                .writable = false,
                .executable = true,
            },
        }
    );

    if (!address_space.map_image(image)) {
        std::cerr << "failed to map composite test image\n";
        return 1;
    }

    const auto analysis = rothalyx::analysis::Analyzer::analyze(image, address_space);
    if (analysis.functions.empty()) {
        std::cerr << "expected at least one function\n";
        return 2;
    }

    const auto& function = analysis.functions.front();
    const auto* recovered_struct = find_struct_prefix_local(function.recovered_types, "rdi.");
    if (recovered_struct == nullptr) {
        std::cerr << "expected recovered struct for rdi-based accesses\n";
        return 3;
    }
    if (!has_field_offset(*recovered_struct, 4) ||
        !has_field_offset(*recovered_struct, 8) ||
        !has_field_offset(*recovered_struct, 12)) {
        std::cerr << "recovered struct fields are incomplete\n";
        return 4;
    }

    const auto* recovered_array = find_array_prefix_local(function.recovered_types, "rsi.");
    if (recovered_array == nullptr) {
        std::cerr << "expected recovered array for rsi-based indexed access\n";
        return 5;
    }
    if (recovered_array->element_size != 4 || recovered_array->element_type != rothalyx::ir::ScalarType::I32 ||
        !recovered_array->indexed_access) {
        std::cerr << "recovered array metadata is incomplete\n";
        return 6;
    }

    const std::string decl_type = rothalyx::type::render_decl_type(
        function.recovered_types,
        recovered_struct->owner_name,
        rothalyx::ir::ScalarType::Pointer
    );
    if (decl_type.find("struct_") != 0 || decl_type.back() != '*') {
        std::cerr << "expected structured declaration type for recovered struct owner\n";
        return 7;
    }

    if (function.decompiled.pseudocode.find("->field_12") == std::string::npos) {
        std::cerr << "expected typed struct store access in decompiler output\n";
        return 8;
    }
    if (function.decompiled.pseudocode.find("arg_1[") == std::string::npos) {
        std::cerr << "expected typed array indexing in decompiler output\n";
        return 9;
    }

    return 0;
}
