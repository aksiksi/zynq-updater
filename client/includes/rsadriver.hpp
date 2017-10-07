#pragma once

#include <string>
#include <stdint.h>
#include <vector>

#include "axidriver.hpp" // for AXIDriver class
#include "utils.hpp" // for IntSplitter and swap_bytes()

// Relevant memory offsets for RSA-512 core (in bytes)
#define RSA_DATA_OFFSET   0x00 // Points to least significant word in the 16 words of input
#define RSA_COMPLETE  0x40
#define RSA_KEY_SELECT    0x40
#define RSA_START_OFFSET  0x44

#define RSA_CHUNK_SIZE    64 // bytes

enum RSAKey {
    D = 1, // Device private key (decryption)
    GU = 5, // Updating org public key (encryption)
    GC = 6  // Confirming org public key (encryption)
};

class RSADriver {
public:
    std::vector<std::string> decrypt(std::string& ciphertext);
    std::vector<std::string> encrypt(std::string& plaintext, RSAKey key);
private:
    AXIDriver axi_driver;

    // Encrypts or decrypts given data, based on provided key
    std::vector<std::string> compute_rsa(std::string& data, RSAKey mode);

    // Write a single 512 bit chunk for decryption
    void write_chunk(const uint32_t* chunk_ptr);

    // Read a single 512 bit chunk
    void read_chunk(std::string& plaintext);
};
