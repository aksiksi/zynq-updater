#include "sha3driver.hpp"

#include <cstring>

void SHA3Driver::reset() {
    this->axi_driver.write(SHA3_RESET_OFFSET, 0x0, AXIDevice::SHA3);
}

std::string SHA3Driver::compute_hash(std::string& input, bool readable) {
    // Reset the core
    this->reset();

    // If input not multiple of 64 bytes, append 0xFFs to the end
    const uint8_t last_block_size = input.size() % 64;
    input.append(HASH_SIZE - last_block_size, 0xFF);

    // Get a pointer to underlying string data
    const uint8_t* ptr = reinterpret_cast<const uint8_t *>(input.data());

    // Number of 32-bit words in the input
    const size_t num_words = input.size() / 4;
    
    uint32_t value;

    // Write each dword to the SHA-3 FIFO address
    for (int i = 0; i < num_words; i++) {
        // Read int from uint8_t *
        std::memcpy(&value, ptr, 4);
        ptr += 4;

    	// Perform a byte swap to account for reading int in little endian form
    	const uint32_t swapped = swap_bytes(value);
        this->axi_driver.write(MSG_DATA_OFFSET, swapped, AXIDevice::SHA3);
    }

    // Start hash computation
    this->axi_driver.write(START_HASH_OFFSET, 0x0, AXIDevice::SHA3);

    // Wait for ready bit
    uint8_t hash_ready = 0;
    while (hash_ready != 1)
        hash_ready = this->axi_driver.read(HASH_READY_OFFSET, AXIDevice::SHA3);

    // Read out the resulting hash
    std::string hash = this->read_hash();
    
    // If readable: return a hex string of the hash
    if (readable)
        return this->convert_hash(hash);
    else
        return hash;
}

std::string SHA3Driver::read_hash() {
    /**
     * Reads hash returned by SHA-3 core from mapped memory in binary format.
     * 
     * Returns: 64 byte string containing the hash.
     */
    // Create a string to hold the hash
    // Allocate enough memory to hold the hash
    std::string hash;
    hash.reserve(HASH_SIZE);

    for (int i = 0; i < HASH_SIZE / 4; i++) {
        const uint32_t value = this->axi_driver.read(HASH_DATA_OFFSET, AXIDevice::SHA3);

        // Split into bytes for string
        IntSplitter.num = value;

        // Iterate over bytes in reverse order to get correct hash ordering
        for (int j = 3; j >= 0; j--) {
            // Convert each byte to a single character and append to hash string
            const uint8_t& c = IntSplitter.bytes[j];
            hash.append(1, c);
        }
    }

    return hash;
}

std::string SHA3Driver::convert_hash(std::string& hash) {
    /**
     * Given a binary hash, returns the hash in readable ASCII hex format.
     * 
     * Returns: 128 byte string containing the readable hash.
     */
    std::string readable;
    readable.reserve(HASH_SIZE * 2);

    for (int i = 0; i < HASH_SIZE; i++) {
        // Get char from underlying string ptr
        const char& c = *(hash.data() + i);

        // Convert each character to two hex digits
        readable.push_back(hex[(c & 0xF0) >> 4]);
        readable.push_back(hex[c & 0xF]);
    }

    return readable;
}
