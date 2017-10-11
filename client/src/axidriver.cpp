#include "axidriver.hpp"

#ifdef __linux__
    #include <cstdio>
    #include <fcntl.h>

    uint8_t* AXIDriver::get_mmap(uint32_t base_addr, size_t length) {
        /**
            Returns mmap() of some length at given base_addr as *ptr
            Note: base_addr must be a multiple of PAGE_SIZE
        */
        int fd = open("/dev/mem", O_RDWR);
        if (fd < 1) {
            std::perror("/dev/mem "); // Prints formatted error
            return NULL;
        }
        
        // http://man7.org/linux/man-pages/man2/mmap.2.html
        return static_cast<uint8_t *>(mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, fd, base_addr));
    }
#endif

uint32_t AXIDriver::read(uint32_t offset) {
    // Get pointer to correct offset
    uint8_t* ptr = this->compute_offset(offset);

    // Read 4 bytes into an int
    uint32_t value;
    std::memcpy(&value, ptr, 4);
    
    return value;
}

void AXIDriver::write(uint32_t offset, uint32_t value) {
    uint8_t* ptr = this->compute_offset(offset);
    std::memcpy(ptr, &value, 4);
}
