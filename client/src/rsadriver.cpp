#include "rsadriver.hpp"

std::string RSADriver::compute_rsa(std::vector<std::string>& data, RSAKey key) {
    /**
     * Given a plaintext or ciphertext in std::vector format, either encrypts or decrypts
     * the data using the RSA core under the given key.
     * 
     * Arguments:
     *     - data: plaintext or ciphertext data in 512 bit chunks (std::vector<std::string>)
     *     - key: key to be used in core (RSAKey)
     * 
     * Procedure:
     * 
     *     1. Iterate over each chunk in data.
     *     2. Encrypt or decrypt the chunk using given key stored in RoT.
     *     3. Append result to output string.
     * 
     * Returns: std::string consisting of the entire result (plaintext or ciphertext)
     */
    // Final output string
    std::string output;
    output.reserve(data.size() * RSA_CHUNK_SIZE);

    // Single chunk result of RSA core (enc or dec)
    std::string result;
    result.reserve(RSA_CHUNK_SIZE);

    // RSA completion flag
    uint8_t rsa_done;

    int idx = 0;

    for (const std::string& chunk: data) {
        // Get a pointer to underlying string data
        // We cast from char* to uint32_t* to process data in 32-bit chunks
        const uint32_t* ptr = reinterpret_cast<const uint32_t *>(chunk.data());

        // Write the current 512-bit chunk to the core
        this->write_chunk(ptr);

        // Select key to be used
        this->axi_driver.write(RSA_KEY_SELECT, key, AXIDevice::RSA);

        // Start the RSA encryption or decryption process
        this->axi_driver.write(RSA_START_OFFSET, 1, AXIDevice::RSA);

        // Wait for completion
        rsa_done = 0;
        while (rsa_done != 3)
            rsa_done = this->axi_driver.read(RSA_COMPLETE, AXIDevice::RSA);

        // Read out plaintext chunk in raw binary format (64 bytes)
        read_chunk(result);

        // Append result to the final output string
        output.insert(idx * RSA_CHUNK_SIZE, result);

        idx++;
    }

    return output;
}

std::string RSADriver::decrypt(const std::string& ciphertext, bool pkcsv15) {
    /**
     * Given a ciphertext in string format, decrypts it using device key,
     * and returns the plaintext.
     * 
     * Arguments:
     *     - ciphertext: encrypted data (string)
     * 
     * Returns: plaintext as vector<string>
     */
    const int num_chunks = ciphertext.size() / RSA_CHUNK_SIZE;
    
    std::vector<std::string> data;
    data.reserve(num_chunks);

    for (int i = 0; i < num_chunks; i++) {
        // Get substring for current chunk
        const std::string& chunk = ciphertext.substr(i * RSA_CHUNK_SIZE, RSA_CHUNK_SIZE);
        data.push_back(chunk);
    }

    std::string plaintext = compute_rsa(data, RSAKey::D_PRV);

    if (pkcsv15) {
        return strip_pkcsv15_padding(plaintext);
    } else {
        return plaintext;
    }
}

std::string RSADriver::strip_pkcsv15_padding(const std::string& plaintext) {
    const int num_chunks = plaintext.size() / RSA_CHUNK_SIZE;
    
    std::string stripped;
    stripped.reserve(num_chunks * PKCSV15_CHUNK_SIZE);

    for (int i = 0; i < num_chunks; i++) {
        // Get a substring with stripped padding (i.e., only chunk data)
        const int chunk_offset = (i * RSA_CHUNK_SIZE) + PKCSV15_PAD_SIZE;
        const std::string& chunk = plaintext.substr(chunk_offset, PKCSV15_PAD_SIZE);

        // Strip pad_size from start of chunk as well (if applicable)
        if (i == num_chunks-1) {
            // Get pad_size as int
            const char* ptr = chunk.data();
            const int pad_size = *ptr++;
            
            // Check for valid padding
            int count = 1;
            for (int j = 1; j < pad_size; j++) {
                if (*ptr++ == pad_size)
                    count++;
            }
            
            // Padding valid -> strip it out of the chunk
            if (count == pad_size) {
                const std::string& s = chunk.substr(pad_size, chunk.size()-pad_size);
                stripped.insert(i * PKCSV15_CHUNK_SIZE, s);
            } else {
                stripped.insert(i * PKCSV15_CHUNK_SIZE, chunk);
            }

        }
    }

    return stripped;
}

std::string RSADriver::encrypt(const std::string& plaintext, RSAKey key, bool pkcsv15) {
    /**
     * Given a plaintext in string format, encrypts it using either GU or GC public key.
     * 
     * Arguments:
     *     - plaintext: plaintext data (string)
     * 
     * Returns: ciphertext as vector<string>
     */
    std::vector<std::string> data;
    
    // Pre-process input plaintext for PKCS#1 v1.5
    if (pkcsv15) {
        const int num_chunks = plaintext.size() / PKCSV15_CHUNK_SIZE;
        const int last_chunk_size = plaintext.size() % PKCSV15_CHUNK_SIZE;

        data.reserve(num_chunks);

        std::string chunk;
        chunk.reserve(RSA_CHUNK_SIZE); // Reserve 64 bytes for output chunk
        
        for (int i = 0; i < num_chunks; i++) {
            // Insert 11 byte padding
            chunk.insert(0, PKCSV15_PADDING);

            // Get pointer to correct position in plaintext string
            const char* pos = plaintext.data() + i * PKCSV15_CHUNK_SIZE;
            
            // Insert 53 byte plaintext chunk after the padding
            chunk.insert(PKCSV15_PAD_SIZE, pos, PKCSV15_CHUNK_SIZE);

            // Append chunk to output vector
            data.push_back(chunk);
            
            chunk.clear();
        }

        // Handle the last chunk
        const int padding_size = PKCSV15_CHUNK_SIZE - last_chunk_size;

        if (padding_size > 0) {
            // Insert 11 byte padding
            chunk.insert(0, PKCSV15_PADDING);

            // Left pad the plaintext with padding_size until it is 53 bytes long
            for (int i = 0; i < padding_size; i++)
                chunk.insert(PKCSV15_PAD_SIZE + i, 1, (char)padding_size);
        
            // Insert actual data to complete the chunk
            const char* pos = plaintext.data() + num_chunks * PKCSV15_CHUNK_SIZE;
            chunk.insert(PKCSV15_PAD_SIZE+padding_size, pos, last_chunk_size);

            data.push_back(chunk);
        }
    }
    
    return compute_rsa(data, key);
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
