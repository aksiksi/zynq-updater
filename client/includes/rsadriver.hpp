#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#include "axidriver.hpp" // for AXIDriver class
#include "utils.hpp" // for IntSplitter and swap_bytes()

#define RSA_BASE_ADDR     FPGA_BASE_ADDR + 0x3C00000

// Relevant memory offsets for RSA-512 core (in bytes)
#define RSA_DATA_START    0x00 // Points to least significant word in the 16 words of input
#define RSA_DATA_END      0x3c // Points to most sig. word in the input
#define RSA_COMPLETE      0x40
#define RSA_KEY_SELECT    0x40
#define RSA_START_OFFSET  0x44
#define RSA_STOP_OFFSET   0x48

#define RSA_CHUNK_SIZE     64 // bytes
#define PKCS1_CHUNK_SIZE   53 // bytes

// PKCS#1 1.5 padding size
#define PKCS1_PAD_SIZE 11

// Indices of required keys as configured in PL (see RSA AXI driver implementation)
enum RSAKey {
    D_PRV = 1, // Device private key (decryption)
    GU_PUB = 5, // Updating org public key (encryption)
    GC_PUB = 6  // Confirming org public key (encryption)
};

class RSADriver : public AXIDriver {
public:
    RSADriver() : AXIDriver(RSA_BASE_ADDR) {}
    std::string decrypt(const std::string& ciphertext);
    std::string encrypt(const std::string& plaintext, RSAKey key);
    bool pkcs1 = true;
private:
    // Encrypts or decrypts given data, based on provided key
    std::string compute_rsa(const std::string& data, RSAKey key);

    // Strip PKCS#1 v1.5 padding from a given decrypted plaintext
    std::string strip_pkcs1_padding(const std::string& plaintext, bool is_last);

    // Write a single 512 bit chunk
    void write_chunk(const std::string& chunk);

    // Read a single 512 bit chunk
    void read_chunk(std::string& chunk);
};
