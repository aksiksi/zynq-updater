#pragma once

#include <string>
#include <stdint.h>
#include <vector>

#include "axidriver.hpp" // for AXIDriver class
#include "utils.hpp" // for IntSplitter and swap_bytes()

// Relevant memory offsets for RSA-512 core (in bytes)
#define RSA_DATA_OFFSET   0x00 // Points to least significant word in the 16 words of input
#define RSA_DECRYPT_DONE  0x40
#define RSA_KEY_SELECT    0x40
#define RSA_START_OFFSET  0x44

// Key number for device
#define DEVICE_KEY_NUM    1

#define RSA_CHUNK_SIZE    64 // bytes

class RSADriver {
public:
    std::vector<std::string> decrypt(std::string& ciphertext);
private:
    AXIDriver axi_driver;

    // Write a single 512 bit chunk for decryption
    void write_chunk(const uint32_t* chunk_ptr);

    // Read a single 512 bit chunk
    void read_chunk(std::string& plaintext);
};
