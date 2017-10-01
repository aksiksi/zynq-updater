#include "sha3driver.hpp"

// Converts from a 32-bit int to a 4 byte array
union {
    uint32_t num;
    uint8_t bytes[4];
} IntSplitter;

void SHA3Driver::reset() {
    this->axi_driver.write(SHA3_RESET_OFFSET, 0x0, AXIDevice::SHA3);
}

std::string SHA3Driver::compute_hash(std::string& input) {
    // Reset the core
    this->reset();

    // Get a pointer to underlying string data
    // We cast from char* to uint32_t* to process data in 32-bit chunks
    const size_t num_blocks = input.size() / 4;
    const uint32_t* ptr = reinterpret_cast<const uint32_t *>(input.data());

    // Write each dword to the SHA-3 FIFO address
    for (int i = 0; i < num_blocks; i++) {
    	// IMPORTANT: Perform a word swap to account for reading int in little endian form
    	const uint32_t swapped = swap_words(*ptr++);
        this->axi_driver.write(MSG_DATA_OFFSET, swapped, AXIDevice::SHA3);
    }

    // Start hash computation
    this->axi_driver.write(START_HASH_OFFSET, 0x0, AXIDevice::SHA3);

    // Wait for ready bit
    uint8_t hash_ready = 0;
    while (hash_ready != 1)
        hash_ready = this->axi_driver.read(HASH_READY_OFFSET, AXIDevice::SHA3);

    // Read out the resulting hash
    return this->read_hash();
}

void SHA3Driver::write_data(const uint32_t* data, size_t num_blocks) {
    // TODO: this only handles a single 512 bit input
    for (int i = 0; i < num_blocks; i++) {
        this->axi_driver.write(MSG_DATA_OFFSET, *(data+i), AXIDevice::SHA3);
    }
}

std::string SHA3Driver::read_hash() {
    /**
     * Reads hash returned by SHA-3 core from memory in binary format.
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
            hash.append(c, 1);
        }
    }

    return hash;
}

std::string SHA3Driver::convert_hash(std::string& hash) {
    /**
     * Given a binary hash, returns the hash in readable ASCII hex format.
     */
    // TODO: test on Zynq
    std::string readable;
    readable.reserve(HASH_SIZE);

    for (int i = 0; i < HASH_SIZE; i++) {
        // Get char from underlying string ptr
        const uint8_t& c = *(uint8_t *)(hash.data() + i);

        // Convert each character to two hex digits
        hash.append(&hex[(c & 0xF0) >> 4], 1);
        hash.append(&hex[c & 0xF], 1);
    }

    return readable;
}
