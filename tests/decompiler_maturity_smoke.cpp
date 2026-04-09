#include <cstdint>
#include <iostream>
#include <vector>

#include "rothalyx/decompiler/decompiler.hpp"

namespace {

rothalyx::disasm::Instruction make_instruction(
    const std::uint64_t address,
    const std::string& mnemonic,
    const rothalyx::disasm::InstructionKind kind = rothalyx::disasm::InstructionKind::Instruction
) {
    return rothalyx::disasm::Instruction{
        .address = address,
        .size = 1,
        .kind = kind,
        .bytes = {0x90},
        .mnemonic = mnemonic,
        .operands = {},
        .decoded_operands = {},
        .control_flow_target = std::nullopt,
        .data_references = {},
    };
}

rothalyx::ir::Value reg(const char* name, const rothalyx::ir::ScalarType type = rothalyx::ir::ScalarType::I32) {
    return rothalyx::ir::Value{
        .kind = rothalyx::ir::ValueKind::Register,
        .type = type,
        .name = name,
    };
}

rothalyx::ir::Value temp(const char* name, const rothalyx::ir::ScalarType type = rothalyx::ir::ScalarType::I32) {
    return rothalyx::ir::Value{
        .kind = rothalyx::ir::ValueKind::Temporary,
        .type = type,
        .name = name,
    };
}

rothalyx::ir::Value imm(const std::int64_t value, const rothalyx::ir::ScalarType type = rothalyx::ir::ScalarType::I64) {
    return rothalyx::ir::Value{
        .kind = rothalyx::ir::ValueKind::Immediate,
        .type = type,
        .immediate = value,
    };
}

rothalyx::ir::Value mem(const char* base, const std::int64_t displacement, const rothalyx::ir::ScalarType type) {
    return rothalyx::ir::Value{
        .kind = rothalyx::ir::ValueKind::MemoryAddress,
        .type = type,
        .memory =
            rothalyx::ir::MemoryAddress{
                .segment = {},
                .base = base,
                .index = {},
                .displacement = displacement,
                .scale = 1,
            },
    };
}

}  // namespace

int main() {
    const auto graph = rothalyx::cfg::FunctionGraph::from_linear(
        "decompiler_quality",
        {
            make_instruction(0x1000, "mov"),
            make_instruction(0x1004, "mov"),
            make_instruction(0x1008, "mov"),
            make_instruction(0x100C, "ret", rothalyx::disasm::InstructionKind::Return),
        }
    );

    const rothalyx::ssa::Function function{
        .name = "decompiler_quality",
        .entry_address = 0x1000,
        .blocks =
            {
                rothalyx::ssa::BasicBlock{
                    .start_address = 0x1000,
                    .phi_nodes = {},
                    .instructions =
                        {
                            rothalyx::ir::Instruction{
                                .address = 0x1000,
                                .kind = rothalyx::ir::InstructionKind::Assign,
                                .destination = reg("sp.0", rothalyx::ir::ScalarType::Pointer),
                                .inputs = {imm(0, rothalyx::ir::ScalarType::Pointer)},
                            },
                            rothalyx::ir::Instruction{
                                .address = 0x1001,
                                .kind = rothalyx::ir::InstructionKind::Assign,
                                .destination = reg("frame.0", rothalyx::ir::ScalarType::Pointer),
                                .inputs = {imm(0, rothalyx::ir::ScalarType::Pointer)},
                            },
                            rothalyx::ir::Instruction{
                                .address = 0x1004,
                                .kind = rothalyx::ir::InstructionKind::Load,
                                .destination = temp("load_0", rothalyx::ir::ScalarType::I32),
                                .inputs = {mem("rdi.0", 4, rothalyx::ir::ScalarType::I32)},
                            },
                            rothalyx::ir::Instruction{
                                .address = 0x1008,
                                .kind = rothalyx::ir::InstructionKind::Store,
                                .inputs =
                                    {
                                        mem("rdi.0", 12, rothalyx::ir::ScalarType::I32),
                                        temp("load_0", rothalyx::ir::ScalarType::I32),
                                    },
                            },
                            rothalyx::ir::Instruction{
                                .address = 0x100C,
                                .kind = rothalyx::ir::InstructionKind::Return,
                                .text = "ret",
                            },
                        },
                    .predecessors = {},
                    .successors = {},
                },
            },
        .immediate_dominators = {},
    };

    rothalyx::type::FunctionTypes recovered_types{
        .variables =
            {
                rothalyx::type::RecoveredVariable{.name = "rdi.0", .type = rothalyx::ir::ScalarType::Pointer},
                rothalyx::type::RecoveredVariable{.name = "sp.0", .type = rothalyx::ir::ScalarType::Pointer},
                rothalyx::type::RecoveredVariable{.name = "frame.0", .type = rothalyx::ir::ScalarType::Pointer},
                rothalyx::type::RecoveredVariable{.name = "load_0", .type = rothalyx::ir::ScalarType::I32},
            },
        .structs =
            {
                rothalyx::type::RecoveredStruct{
                    .owner_name = "rdi.0",
                    .type_name = "widget",
                    .fields =
                        {
                            rothalyx::type::RecoveredStructField{
                                .name = "field_4",
                                .offset = 4,
                                .size = 4,
                                .type = rothalyx::ir::ScalarType::I32,
                            },
                            rothalyx::type::RecoveredStructField{
                                .name = "field_12",
                                .offset = 12,
                                .size = 4,
                                .type = rothalyx::ir::ScalarType::I32,
                            },
                        },
                },
            },
        .arrays = {},
    };

    const auto decompiled = rothalyx::decompiler::Decompiler::decompile(graph, function, recovered_types);
    if (decompiled.pseudocode.find("struct widget {") == std::string::npos ||
        decompiled.pseudocode.find("int32_t field_4;") == std::string::npos ||
        decompiled.pseudocode.find("int32_t field_12;") == std::string::npos) {
        std::cerr << "expected recovered struct definitions in pseudocode\n";
        return 1;
    }
    if (decompiled.pseudocode.find("widget* arg_0") == std::string::npos) {
        std::cerr << "expected recovered struct type on the argument\n";
        return 2;
    }
    if (decompiled.pseudocode.find("arg_0->field_12 = arg_0->field_4;") == std::string::npos) {
        std::cerr << "expected typed and inlined struct access in pseudocode\n";
        return 3;
    }
    if (decompiled.pseudocode.find("stack_temp") != std::string::npos ||
        decompiled.pseudocode.find("frame_temp") != std::string::npos ||
        decompiled.pseudocode.find("loaded_value") != std::string::npos) {
        std::cerr << "expected decompiler to suppress temporary/noise locals\n";
        return 4;
    }

    return 0;
}
