#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>

#include "deps/sha3driver.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: sha3 <path_to_file*>" << std::endl;
    }

    for (int i = 1; i < argc; i++) {
        // Load file from disk
        std::ifstream in_file (argv[i], std::ios::binary | std::ios::out);
    
        // Read file into a single string
        std::ostringstream oss;
        oss << in_file.rdbuf();
        std::string contents = oss.str();
        in_file.close();
    
        // Run file through SHA-3 core
        SHA3Driver driver;

        // Time the hashing process
        std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
        const std::string hash = driver.compute_hash(contents, true);
        std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
        
        std::cout << "Result for " << argv[i] << ": " << hash << " Duration: " << duration << std::endl;
    }

    return 0;
}
