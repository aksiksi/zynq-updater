#pragma once

#include <stdint.h>

// Converts from a 32-bit int to a 4 byte array
union {
    uint32_t num;
    uint8_t bytes[4];
} IntSplitter;

inline uint32_t swap_words(const uint32_t& value) {
    // Swaps the two 16-bit words in a unsigned 32-bit dword
    return ((value & 0x0000FFFF) << 0x10) | ((value & 0xFFFF0000) >> 0x10);
}
