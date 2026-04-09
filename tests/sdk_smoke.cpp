#include <array>
#include <filesystem>
#include <iostream>
#include <string>

#include "rothalyx/sdk/api.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: rothalyx_sdk_smoke <debuggee>\n";
        return 1;
    }

    const std::filesystem::path binary_path(argv[1]);
    const std::filesystem::path project_path = std::filesystem::temp_directory_path() / "rothalyx_sdk_smoke.sqlite";
    std::error_code error_code;
    std::filesystem::remove(project_path, error_code);

    std::array<char, 512> error{};
    const auto analyze_status =
        rothalyx_sdk_analyze_binary(binary_path.string().c_str(), project_path.string().c_str(), nullptr, error.data(), error.size());
    if (analyze_status != ROTHALYX_SDK_STATUS_OK) {
        std::cerr << "analyze failed: " << error.data() << '\n';
        return 2;
    }

    rothalyx_project_t* project = nullptr;
    const auto open_status = rothalyx_sdk_open_project(project_path.string().c_str(), &project, error.data(), error.size());
    if (open_status != ROTHALYX_SDK_STATUS_OK || project == nullptr) {
        std::cerr << "open failed: " << error.data() << '\n';
        return 3;
    }

    rothalyx_run_overview_t run{};
    if (rothalyx_sdk_get_latest_run(project, &run, error.data(), error.size()) != ROTHALYX_SDK_STATUS_OK) {
        rothalyx_sdk_close_project(project);
        std::cerr << "load latest run failed: " << error.data() << '\n';
        return 4;
    }

    if (run.run_id <= 0 || run.function_count <= 0 || std::string(run.ai_backend) != "heuristic") {
        rothalyx_sdk_close_project(project);
        std::cerr << "unexpected run overview\n";
        return 5;
    }

    size_t function_count = 0;
    if (rothalyx_sdk_get_function_count(project, run.run_id, &function_count, error.data(), error.size()) != ROTHALYX_SDK_STATUS_OK) {
        rothalyx_sdk_close_project(project);
        std::cerr << "function count failed: " << error.data() << '\n';
        return 6;
    }

    if (function_count == 0) {
        rothalyx_sdk_close_project(project);
        std::cerr << "expected persisted functions\n";
        return 7;
    }

    rothalyx_function_record_t function{};
    if (rothalyx_sdk_get_function_at(project, run.run_id, 0, &function, error.data(), error.size()) != ROTHALYX_SDK_STATUS_OK) {
        rothalyx_sdk_close_project(project);
        std::cerr << "function fetch failed: " << error.data() << '\n';
        return 8;
    }

    if (function.name == nullptr || *function.name == '\0' || function.entry_address == 0) {
        rothalyx_sdk_close_project(project);
        std::cerr << "unexpected function record\n";
        return 9;
    }

    size_t insight_count = 0;
    if (rothalyx_sdk_get_ai_insight_count(project, run.run_id, &insight_count, error.data(), error.size()) != ROTHALYX_SDK_STATUS_OK) {
        rothalyx_sdk_close_project(project);
        std::cerr << "ai insight count failed: " << error.data() << '\n';
        return 10;
    }

    if (insight_count == 0) {
        rothalyx_sdk_close_project(project);
        std::cerr << "expected persisted ai insights\n";
        return 11;
    }

    rothalyx_ai_insight_record_t insight{};
    if (rothalyx_sdk_get_ai_insight_at(project, run.run_id, 0, &insight, error.data(), error.size()) != ROTHALYX_SDK_STATUS_OK) {
        rothalyx_sdk_close_project(project);
        std::cerr << "ai insight fetch failed: " << error.data() << '\n';
        return 12;
    }

    if (insight.summary == nullptr || *insight.summary == '\0') {
        rothalyx_sdk_close_project(project);
        std::cerr << "expected non-empty ai summary\n";
        return 13;
    }

    if (std::string(rothalyx_sdk_version_string()) != "1.0.3" || rothalyx_sdk_abi_version() != 1U) {
        rothalyx_sdk_close_project(project);
        std::cerr << "unexpected sdk version metadata\n";
        return 14;
    }

    rothalyx_sdk_close_project(project);
    std::filesystem::remove(project_path, error_code);
    return 0;
}
