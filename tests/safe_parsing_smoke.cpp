#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "zara/loader/binary_image.hpp"

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: safe_parsing_smoke <fixture-binary>\n";
        return 1;
    }

    const std::filesystem::path fixture_binary = argv[1];
    const auto raw_path = std::filesystem::temp_directory_path() / "zara_safe_parsing_raw.bin";
    {
        std::ofstream stream(raw_path, std::ios::binary);
        const std::vector<char> payload(8, '\x90');
        stream.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    }

    zara::loader::BinaryImage image;
    std::string error;

    zara::loader::LoadOptions options;
    options.policy.max_path_length = 4;
    if (zara::loader::BinaryImage::load_from_file(raw_path, image, error, options)) {
        std::cerr << "expected input path policy to reject oversized path\n";
        return 2;
    }

    options = {};
    options.policy.max_file_size_bytes = 4;
    if (zara::loader::BinaryImage::load_from_file(raw_path, image, error, options)) {
        std::cerr << "expected raw file size policy to reject oversized input\n";
        return 3;
    }

    options = {};
    options.policy.max_file_size_bytes = 64;
    options.policy.max_mapped_section_size = 4;
    if (zara::loader::BinaryImage::load_from_file(raw_path, image, error, options)) {
        std::cerr << "expected raw mapping size policy to reject oversized mapping\n";
        return 4;
    }

    options = {};
    options.policy.max_section_name_length = 2;
    if (zara::loader::BinaryImage::load_from_file(raw_path, image, error, options)) {
        std::cerr << "expected raw section name policy to reject oversized section name\n";
        return 5;
    }

    options = {};
    options.policy.max_section_count = 1;
    if (zara::loader::BinaryImage::load_from_file(fixture_binary, image, error, options)) {
        std::cerr << "expected structured binary section policy to reject the fixture\n";
        return 6;
    }

    options = {};
    if (!zara::loader::BinaryImage::load_from_file(fixture_binary, image, error, options)) {
        std::cerr << "expected fixture to load with default parse policy: " << error << '\n';
        return 7;
    }

    return 0;
}
