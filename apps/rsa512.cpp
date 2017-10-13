#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>

#include "deps/rsadriver.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cout << "Usage: rsa512 <path_to_file*>" << std::endl;
    }

    for (int i = 1; i < argc; i++) {
        // Load file from disk
        std::ifstream in_file (argv[i], std::ios::binary | std::ios::out);
    
        // Read file into a single string
        std::ostringstream oss;
        oss << in_file.rdbuf();
        const std::string contents = oss.str();
        in_file.close();
    
        // Run file through RSA-512 core with device encryption key
        RSADriver driver;

        // Time the hashing process
        std::chrono::high_resolution_clock::time_point t1 = std::chrono::high_resolution_clock::now();
        const std::string enc = driver.encrypt(contents, RSAKey::D_PRV);
        std::chrono::high_resolution_clock::time_point t2 = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count();
        
        std::cout << "Duration for " << argv[i] << ": " << duration << std::endl;
    }

    return 0;
}