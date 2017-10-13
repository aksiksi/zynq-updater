#include <iostream>

#include "deps/axidriver.hpp"
#include "deps/utils.hpp"

#define DEVICE_DNA_ADDRESS 0x43C30000

int main() {
    AXIDriver dna_driver (DEVICE_DNA_ADDRESS);

    uint32_t w1 = swap_bytes(dna_driver.read(0));
    uint32_t w2 = swap_bytes(dna_driver.read(4));

    std::cout << "DeviceDNA = " << w1 << w2 << std::endl;

    return 0;
}
