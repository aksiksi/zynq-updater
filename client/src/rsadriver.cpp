#include "rsadriver.hpp"

std::vector<std::string> RSADriver::decrypt(std::string& ciphertext) {
    /**
     * Given a ciphertext in string format, decrypts the ciphertext using the RSA
     * core under the given key.
     * 
     * Arguments:
     *     - ciphertext: encrypted data (string)
     * 
     * Procedure:
     * 
     *     1. Split string into 512 bit chunks for decryption.
     *     2. Decrypt each chunk using device private key (stored on RoT).
     *     3. Append chunk to plaintext string vector.
     */
    const size_t num_chunks = ciphertext.size() / RSA_CHUNK_SIZE;

    // TODO: handle case of input not multiple of 512 bits
    // if (encrypted.size() % 64 != 0) {}

    // Get a pointer to underlying string data
    // We cast from char* to uint32_t* to process data in 32-bit chunks
    const uint32_t* ptr = reinterpret_cast<const uint32_t *>(ciphertext.data());

    uint8_t rsa_done;
    std::string chunk;
    chunk.reserve(RSA_CHUNK_SIZE);

    std::vector<std::string> plaintext;
    plaintext.reserve(num_chunks);
    
    for (int i = 0; i < num_chunks; i++) {
        // Write each 512-bit chunk to the core
        // Offset the pointer correctly so that it starts at the correct position in the ciphertext
        this->write_chunk(ptr + (i * RSA_CHUNK_SIZE));

        // Select key for decryption
        this->axi_driver.write(RSA_KEY_SELECT, DEVICE_KEY_NUM, AXIDevice::RSA);

        // Start the RSA decryption process
        this->axi_driver.write(RSA_START_OFFSET, 1, AXIDevice::RSA);

        // Wait for completion
        rsa_done = 0;
        while (rsa_done != 3)
            rsa_done = this->axi_driver.read(RSA_DECRYPT_DONE, AXIDevice::RSA);

        // Read out plaintext chunk in binary format
        read_chunk(chunk);

        // Append to the final vector
        plaintext.push_back(chunk);
    }

    return plaintext;
}

void RSADriver::write_chunk(const uint32_t* chunk) {
    /**
     * Given a 512-bit chunk, write it to the correct location to be used
     * in decryption by the RSA core.
     */

    // Iterate over each dword in the chunk
    for (int i = 0; i < RSA_CHUNK_SIZE; i += 4) {
        // Perform little endian word swap
        const uint32_t swapped = swap_words(*chunk++);

        // Write the word to the correct offset
        this->axi_driver.write(RSA_DATA_OFFSET + i, swapped, AXIDevice::RSA);
    }
}

void RSADriver::read_chunk(std::string& plaintext) {
    for (int i = 0; i < RSA_CHUNK_SIZE; i += 4) {
        // Read one dword of the decrypted chunk
        const uint32_t& value = this->axi_driver.read(RSA_DATA_OFFSET, AXIDevice::RSA);

        // Split into bytes for adding to string
        IntSplitter.num = value;

        // Iterate over bytes in reverse order to get correct ordering (little endian :/)
        for (int j = 3; j >= 0; j--) {
            const uint8_t& c = IntSplitter.bytes[j];
            plaintext.append(c, 1);
        }
    }
}
