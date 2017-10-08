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
#define RSA_BASE_ADDR    FPGA_BASE_ADDR + 0x3C00000
#define HASH_BASE_ADDR   FPGA_BASE_ADDR + 0x3C10000
#define SHA3_BASE_ADDR   FPGA_BASE_ADDR + 0x3C20000

// AXI parameters
#define AXI_WIDTH 4 // bytes

// 64K allocated to each AXI device
#define DEVICE_MEM_SPACE PAGE_SIZE * 16

enum AXIDevice {
    RSA,
    SHA3,
    COMP,
};

class AXIDriver {
public:
    AXIDriver() {
        #ifdef __linux__
            // TODO: error handling
            rsa_mem = this->get_mmap(RSA_BASE_ADDR,  DEVICE_MEM_SPACE);
            sha3_mem = this->get_mmap(SHA3_BASE_ADDR, DEVICE_MEM_SPACE);
            comp_mem = this->get_mmap(HASH_BASE_ADDR, DEVICE_MEM_SPACE);
        #else
            rsa_mem = (uint8_t *)RSA_BASE_ADDR;
            sha3_mem = (uint8_t *)SHA3_BASE_ADDR;
            comp_mem = (uint8_t *)HASH_BASE_ADDR;
        #endif
    }

    ~AXIDriver() {
        #ifdef __linux__
            munmap(rsa_mem, PAGE_SIZE);
            munmap(sha3_mem, PAGE_SIZE);
            munmap(comp_mem, PAGE_SIZE);
        #endif
    }

    // Read a single 32-bit value from device memorys
    uint32_t read(uint32_t offset, AXIDevice d);

    // Write a single 32-bit value to device memory
    void write(uint32_t offset, uint32_t value, AXIDevice d);

private:
    uint8_t *rsa_mem;  // RSA-512 memory
    uint8_t *sha3_mem; // SHA3 memory
    uint8_t *comp_mem; // Hash comparator memory

    #ifdef __linux__
        // Returns mmap() of some length at given base_addr as a *ptr
        uint8_t* get_mmap(uint32_t base_addr, size_t length);
    #endif

    inline uint8_t* compute_offset(uint32_t offset, AXIDevice d) {
        /**
            Computes the offset (in bytes) relative to device base address.
            Returns uint8_t pointer starting at that address.
        */
        switch (d) {
            case AXIDevice::RSA:
                return rsa_mem + offset;
            case AXIDevice::SHA3:
                return sha3_mem + offset;
            case AXIDevice::COMP:
                return comp_mem + offset;
        }
    }
};
