#pragma once

#include <cstdint>
#include <cstring>

#ifdef __linux__
    #include <sys/mman.h>
#endif

// Zynq Linux kernel page size
#define PAGE_SIZE 4096

// Base addresses as configured in HDF
#define FPGA_BASE_ADDR   0x40000000

// AXI parameters
#define AXI_WIDTH 4 // bytes

// 64K allocated to each AXI device
#define DEVICE_MEM_SPACE PAGE_SIZE * 16

class AXIDriver {
public:
    AXIDriver(uint32_t base_address) {
        #ifdef __linux__
            // TODO: error handling
            mem = this->get_mmap(base_address, PAGE_SIZE);
        #else
            mem = (uint8_t *)base_address;
        #endif
    }

    ~AXIDriver() {
        #ifdef __linux__
            munmap(mem, PAGE_SIZE);
        #endif
    }

    // Read a single 32-bit value from AXI device memory
    uint32_t read(uint32_t offset);

    // Write a single 32-bit value to AXI device memory
    void write(uint32_t offset, uint32_t value);

private:
    // Points to start of AXI components mem space
    uint8_t *mem;

    #ifdef __linux__
        // Returns mmap() of some length at given base_addr as a *ptr
        uint8_t* get_mmap(uint32_t base_addr, size_t length);
    #endif

    inline uint8_t* compute_offset(uint32_t offset) {
        /**
            Computes the offset (in bytes) relative to device base address.
            Returns uint8_t pointer starting at that address.
        */
        return mem + offset;
    }
};
