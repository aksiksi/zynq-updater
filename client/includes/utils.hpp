#pragma once

#include <cstdint>

// Converts from a 32-bit int to a 4 byte array
union {
    uint32_t num;
    uint8_t bytes[4];
} IntSplitter;

inline uint32_t swap_bytes(const uint32_t& value) {
    // Swaps the the ordering of bytes in a 4 byte word
    return ((value & 0x000000FF) << 24) | 
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0xFF000000) >> 24);
}
