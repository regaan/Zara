#include <filesystem>
#include <iostream>
#include <string>

#include "rothalyx/scripting/python_engine.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: rothalyx_scripting_smoke <binary>\n";
        return 1;
    }

    const std::filesystem::path binary_path = std::filesystem::absolute(argv[1]);
    const auto temp_root = std::filesystem::temp_directory_path() / "rothalyx_scripting_smoke";
    const auto input_root = temp_root / "inputs";
    const auto output_root = temp_root / "output";
    std::error_code filesystem_error;
    std::filesystem::remove_all(temp_root, filesystem_error);
    std::filesystem::create_directories(input_root, filesystem_error);
    std::filesystem::copy_file(
        binary_path,
        input_root / binary_path.filename(),
        std::filesystem::copy_options::overwrite_existing,
        filesystem_error
    );

    rothalyx::scripting::PythonEngine engine;
    if (!engine.is_available()) {
        std::cerr << "embedded python is unavailable\n";
        return 2;
    }

    std::string error;
    if (!engine.set_argv({"scripting_smoke", binary_path.string()}, error)) {
        std::cerr << "set_argv failed: " << error << '\n';
        return 3;
    }

    const std::string script =
        "from pathlib import Path\n"
        "import rothalyx\n"
        "input_root = Path(r'" + input_root.string() + "')\n"
        "output_root = Path(r'" + output_root.string() + "')\n"
        "discovered = rothalyx.discover_inputs(str(input_root), recursive=False)\n"
        "assert len(discovered) == 1\n"
        "batch = rothalyx.run_batch(discovered, str(output_root), concurrency=1, write_reports=True)\n"
        "assert batch['success_count'] == 1 and batch['failure_count'] == 0\n"
        "assert (output_root / 'manifest.tsv').exists()\n"
        "assert (output_root / 'summary.json').exists()\n"
        "summary = rothalyx.analyze_binary(r'" + binary_path.string() + "')\n"
        "assert summary['function_count'] > 0\n"
        "functions = rothalyx.list_functions(r'" + binary_path.string() + "', limit=8)\n"
        "assert len(functions) > 0\n"
        "details = rothalyx.get_function(r'" + binary_path.string() + "', functions[0]['entry'])\n"
        "assert 'instructions_detail' in details and len(details['instructions_detail']) > 0\n"
        "assert 'outgoing_calls' in details\n"
        "imports = rothalyx.list_imports(r'" + binary_path.string() + "', limit=8)\n"
        "exports = rothalyx.list_exports(r'" + binary_path.string() + "', limit=8)\n"
        "strings = rothalyx.list_strings(r'" + binary_path.string() + "', limit=8)\n"
        "xrefs = rothalyx.list_xrefs(r'" + binary_path.string() + "', limit=8)\n"
        "calls = rothalyx.list_call_graph(r'" + binary_path.string() + "', limit=8)\n"
        "insights = rothalyx.get_ai_insights(r'" + binary_path.string() + "', limit=8)\n"
        "security = rothalyx.get_security_report(r'" + binary_path.string() + "', max_findings=8, max_gadgets=8)\n"
        "diff = rothalyx.diff_binaries(r'" + binary_path.string() + "', r'" + binary_path.string() + "')\n"
        "assert isinstance(imports, list)\n"
        "assert isinstance(exports, list)\n"
        "assert isinstance(strings, list)\n"
        "assert isinstance(xrefs, list)\n"
        "assert len(calls) > 0\n"
        "assert len(insights) > 0\n"
        "assert 'findings' in security and 'gadgets' in security\n"
        "assert 'patterns' in insights[0] and 'vulnerability_hints' in insights[0]\n"
        "assert 'patterns' in security and 'poc_targets' in security\n"
        "assert diff['unchanged_count'] > 0\n"
        "summary_detail = rothalyx.get_function_summary(r'" + binary_path.string() + "', functions[0]['entry'])\n"
        "ir_blocks = rothalyx.get_function_ir(r'" + binary_path.string() + "', functions[0]['entry'])\n"
        "ssa_blocks = rothalyx.get_function_ssa(r'" + binary_path.string() + "', functions[0]['entry'])\n"
        "assert 'loops' in summary_detail and 'switches' in summary_detail\n"
        "assert isinstance(ir_blocks, list) and len(ir_blocks) > 0\n"
        "assert isinstance(ssa_blocks, list) and len(ssa_blocks) > 0\n"
        "text = rothalyx.decompile_function(r'" + binary_path.string() + "', functions[0]['entry'])\n"
        "assert functions[0]['name'] in text\n"
        "snapshot = rothalyx.capture_entry_snapshot(r'" + binary_path.string() + "')\n"
        "assert 'location' in snapshot and snapshot['location'] is not None\n"
        "assert snapshot['location']['function_name']\n"
        "rothalyx.clear_cache()\n";

    if (!engine.execute_string(script, error)) {
        std::cerr << "script execution failed: " << error << '\n';
        return 4;
    }

    return 0;
}
