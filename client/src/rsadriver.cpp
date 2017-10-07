#include "rsadriver.hpp"

std::vector<std::string> RSADriver::compute_rsa(std::string& data, RSAKey key) {
    /**
     * Given a plaintext or ciphertext in string format, either encrypts or decrypts
     * the data using the RSA core under the given key.
     * 
     * Arguments:
     *     - data: plaintext or ciphertext data (string)
     *     - key: key to be used in core (RSAKey)
     * 
     * Procedure:
     * 
     *     1. Split string into 512 bit chunks.
     *     2. Encrypt or decrypt each chunk using device private key (stored on RoT).
     *     3. Append chunk to output string vector.
     * 
     * Returns: vector<string>, where each string contains a single 512-bit chunk of data
     */
    // Calculate number of 512 bit chunks in data
    const size_t num_chunks = data.size() / RSA_CHUNK_SIZE;
    
    // TODO: handle case of input not multiple of 512 bits
    // if (encrypted.size() % 64 != 0) {}

    // Get a pointer to underlying string data
    // We cast from char* to uint32_t* to process data in 32-bit chunks
    const uint32_t* ptr = reinterpret_cast<const uint32_t *>(data.data());

    uint8_t rsa_done;

    std::string chunk;
    chunk.reserve(RSA_CHUNK_SIZE);
    
    // Final output consisting of encrypted/decrypted data
    std::vector<std::string> output;
    output.reserve(num_chunks);
    
    for (int i = 0; i < num_chunks; i++) {
        // Write each 512-bit chunk to the core
        // Offset the pointer correctly so that it starts at the correct position in the ciphertext
        this->write_chunk(ptr + (i * RSA_CHUNK_SIZE));

        // Select key
        this->axi_driver.write(RSA_KEY_SELECT, key, AXIDevice::RSA);

        // Start the RSA encryption or decryption process
        this->axi_driver.write(RSA_START_OFFSET, 1, AXIDevice::RSA);

        // Wait for completion
        rsa_done = 0;
        while (rsa_done != 3)
            rsa_done = this->axi_driver.read(RSA_COMPLETE, AXIDevice::RSA);

        // Read out plaintext chunk in binary format
        read_chunk(chunk);

        // Append to the final vector
        output.push_back(chunk);
    }

    return output;
}

std::vector<std::string> RSADriver::decrypt(std::string& ciphertext) {
    /**
     * Given a ciphertext in string format, decrypts it using device key,
     * and returns the plaintext.
     * 
     * Arguments:
     *     - ciphertext: encrypted data (string)
     * 
     * Returns: plaintext as vector<string>
     */
    return compute_rsa(ciphertext, RSAKey::D);
}

std::vector<std::string> RSADriver::encrypt(std::string& plaintext, RSAKey key) {
    /**
     * Given a plaintext in string format, encrypts it using either GU or GC public key.
     * 
     * Arguments:
     *     - plaintext: plaintext data (string)
     * 
     * Returns: ciphertext as vector<string>
     */
    return compute_rsa(plaintext, key);
}

void RSADriver::write_chunk(const uint32_t* chunk_ptr) {
    /**
     * Given a 512-bit chunk, write it to the correct location to be used
     * in decryption by the RSA core.
     */

    // Iterate over each dword in the chunk
    for (int i = 0; i < RSA_CHUNK_SIZE; i += 4) {
        // Perform little endian word swap
        const uint32_t swapped = swap_words(*(chunk_ptr + i));

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
