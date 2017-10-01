#pragma once

#include <string>

#include "axidriver.hpp"

// SHA3 parameters (in bytes)
#define INPUT_SIZE 64
#define HASH_SIZE  64

// SHA3 register offsets (in bytes)
#define SHA3_RESET_OFFSET   0x4
#define START_HASH_OFFSET   0x8
#define HASH_READY_OFFSET   0xC
#define FIFO_FULL_OFFSET    0x10
#define HASH_DATA_OFFSET    0x2C
#define MSG_DATA_OFFSET     0x40
#define BYTE_NUM_OFFSET     0x48

const char hex[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

class SHA3Driver {
public:
    void reset();
    std::string compute_hash(std::string& data);
private:
    AXIDriver axi_driver;
    void write_data(const uint32_t* data, size_t num_blocks);
    std::string read_hash();
};
