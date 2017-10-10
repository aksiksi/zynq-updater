#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#include "axidriver.hpp" // for AXIDriver class
#include "utils.hpp" // for IntSplitter and swap_bytes()

// Relevant memory offsets for RSA-512 core (in bytes)
#define RSA_DATA_START    0x00 // Points to least significant word in the 16 words of input
#define RSA_DATA_END      0x3c // Points to most sig. word in the input
#define RSA_COMPLETE      0x40
#define RSA_KEY_SELECT    0x40
#define RSA_START_OFFSET  0x44
#define RSA_STOP_OFFSET   0x48

#define RSA_CHUNK_SIZE     64 // bytes
#define PKCSV15_CHUNK_SIZE 53 // bytes

// PKCS#1 1.5 padding: 00 || 02 || 8 bytes of junk || 00
#define PKCSV15_PAD_SIZE 11
const char PKCSV15_PADDING[PKCSV15_PAD_SIZE] = {0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00};

// Indices of required keys as configured in PL (see RSA AXI driver implementation)
enum RSAKey {
    D_PRV = 1, // Device private key (decryption)
    GU_PUB = 5, // Updating org public key (encryption)
    GC_PUB = 6  // Confirming org public key (encryption)
};

class RSADriver {
public:
    std::string decrypt(const std::string& ciphertext);
    std::string encrypt(const std::string& plaintext, RSAKey key);
    inline void toggle_pkcsv15() { !this->pkcsv15; }
private:
    AXIDriver axi_driver;
    bool pkcsv15 = false;

    // Encrypts or decrypts given data, based on provided key
    std::string compute_rsa(std::vector<std::string>& data, RSAKey key);

    // Strip PKCS#1 v1.5 padding from a given decrypted plaintext
    std::string strip_pkcsv15_padding(const std::string& plaintext);

    // Write a single 512 bit chunk for decryption
    void write_chunk(const uint8_t* chunk_ptr);

    // Read a single 512 bit chunk
    void read_chunk(std::string& plaintext);
};
