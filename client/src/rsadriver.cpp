#include "rsadriver.hpp"

std::string RSADriver::compute_rsa(const std::string& data, RSAKey key) {
    /**
     * Given a plaintext or ciphertext chunk as string, either encrypts or decrypts
     * the data using the RSA core under the given key.
     * 
     * Arguments:
     *     - data: single plaintext or ciphertext data in 512 bit chunk
     *     - key: key to be used in core (RSAKey)
     * 
     * Returns: std::string consisting of the result (plaintext or ciphertext)
     */
    // Single chunk result of RSA core (enc or dec)
    std::string result;
    result.reserve(RSA_CHUNK_SIZE);

    // RSA completion flag
    uint8_t rsa_done;

    // Write the 512-bit chunk to the core
    this->write_chunk(data);

    // Select key to be used
    this->write(RSA_KEY_SELECT, key);

    // Start the RSA encryption or decryption process
    this->write(RSA_START_OFFSET, 1);

    // Send a stop signal to the RSA core to prevent looping behavior (?)
    this->write(RSA_STOP_OFFSET, 0);

    // Wait for completion
    rsa_done = 0;
    while (rsa_done != 3)
        rsa_done = this->read(RSA_COMPLETE);

    // Read out plaintext chunk in raw binary format (64 bytes)
    read_chunk(result);

    return result;
}

std::string RSADriver::decrypt(const std::string& ciphertext) {
    /**
     * Given a ciphertext in string format, decrypts it using device key,
     * and returns the plaintext.
     * 
     * Arguments:
     *     - ciphertext: encrypted data (string)
     * 
     * Returns: plaintext as std::string
     */
    const int num_chunks = ciphertext.size() / RSA_CHUNK_SIZE;

    // Reserve memory for result of decryption
    std::string plaintext;
    plaintext.reserve(num_chunks * PKCS1_CHUNK_SIZE);

    std::string stripped, decrypted;

    for (int i = 0; i < num_chunks; i++) {
        // Get substring for current chunk
        const std::string& chunk = ciphertext.substr(i * RSA_CHUNK_SIZE, RSA_CHUNK_SIZE);
        
        // Decrypt using RSA core
        decrypted = this->compute_rsa(chunk, RSAKey::D_PRV);

        // Strip PKCS1 padding and append to final result
        if (i == num_chunks-1)
            stripped = this->strip_pkcs1_padding(decrypted, true);
        else
            stripped = this->strip_pkcs1_padding(decrypted, false);
        
        plaintext.append(stripped);
    }

    return plaintext;
}

std::string RSADriver::strip_pkcs1_padding(const std::string& plaintext, bool is_last) {
    /**
     * Given a single plaintext string block, strips all padding from the string and returns original message.
     * 
     * Removes the standard PKCS#1 v1.5 padding as well as the last chunk length padding.
     */
    // Get a substring with stripped padding (i.e., only chunk data)
    const std::string chunk = plaintext.substr(PKCS1_PAD_SIZE, PKCS1_CHUNK_SIZE);

    // Strip pad_size from start of chunk as well
    if (is_last) {
        // Get pad_size
        const uint8_t pad_size = (uint8_t)chunk.at(0);

        // Padding invalid -> return the chunk as-is
        if (pad_size >= PKCS1_CHUNK_SIZE)
            return chunk;
        
        // Check for valid padding
        uint8_t count = 1;
        for (uint8_t i = 1; i < pad_size; i++) {
            if ((uint8_t)chunk.at(i) == pad_size)
                count++;
        }
        
        // Padding valid -> strip it out of the chunk and return
        if (count == pad_size) {
            return chunk.substr(pad_size, chunk.size()-pad_size);
        }
    }
    
    // Return chunk by default
    return chunk;
}

std::string RSADriver::encrypt(const std::string& plaintext, RSAKey key) {
    /**
     * Given a plaintext in string format, encrypts it using either GU or GC public key.
     * 
     * Arguments:
     *     - plaintext: plaintext data (string)
     * 
     * Returns: ciphertext as vector<string>
     */
    int num_chunks = plaintext.size() / PKCS1_CHUNK_SIZE;
    const int last_chunk_size = plaintext.size() % PKCS1_CHUNK_SIZE;

    std::string ciphertext;
    ciphertext.reserve(num_chunks * RSA_CHUNK_SIZE);

    std::string padded, cipher;
    padded.reserve(RSA_CHUNK_SIZE);

    for (int i = 0; i < num_chunks; i++) {
        // Get plaintext chunk
        const std::string& chunk = plaintext.substr(i * PKCS1_CHUNK_SIZE, PKCS1_CHUNK_SIZE);

        // Add PKCS1 padding to the chunk
        padded.append(PKCS1_PADDING, PKCS1_PAD_SIZE);

        // Add actual data
        padded.append(chunk);

        // Encrypt using RSA
        cipher = this->compute_rsa(padded, key);

        ciphertext.append(cipher);

        padded.clear();
        cipher.clear();
    }

    // Handle the last chunk if it is not exactly the required size
    if (last_chunk_size != 0) {
        const std::string& chunk = plaintext.substr(num_chunks * PKCS1_CHUNK_SIZE, last_chunk_size);
        const int padding_size = PKCS1_CHUNK_SIZE - last_chunk_size;
        
        // Insert 11 byte PKCS1 v1.5 padding
        padded.append(PKCS1_PADDING, PKCS1_PAD_SIZE);
        
        // Left pad the plaintext with padding_size until it is 53 bytes long
        for (int i = 0; i < padding_size; i++)
            padded.append(1, (char)padding_size);
    
        // Insert actual data to complete the chunk
        padded.append(chunk);

        // Encrypt using RSA
        cipher = this->compute_rsa(padded, key);

        ciphertext.append(cipher);
    }
    
    return ciphertext;
}

void RSADriver::write_chunk(const std::string& chunk) {
    /**
     * Given a 512-bit chunk, write it to the correct location to be used
     * by the RSA core for decryption or encryption.
     */
    uint32_t value;

    // Get raw pointer to string data
    const uint8_t* ptr = reinterpret_cast<const uint8_t *>(chunk.data());

    // Iterate over each dword in the chunk
    for (int i = 0; i < RSA_CHUNK_SIZE; i += 4) {
        // Read from pointer into uint32_t
        std::memcpy(&value, ptr, 4);
        ptr += 4;

        // Perform little endian byte swap
        const uint32_t swapped = swap_bytes(value);

        // Write the word to the correct offset
        // Write words to highest RSA AXI address and move downwards
        this->write(RSA_DATA_END - i, swapped);
    }
}

void RSADriver::read_chunk(std::string& chunk) {
    for (int i = 0; i < RSA_CHUNK_SIZE; i += 4) {
        // Read one dword of the decrypted chunk
        // Start from the last word in the RSA core address space and move down
        const uint32_t& value = this->read(RSA_DATA_END - i);

        // Split into bytes for adding to string
        IntSplitter.num = value;

        // Iterate over bytes in reverse order to get correct ordering (little endian :/)
        for (int j = 3; j >= 0; j--) {
            const uint8_t& c = IntSplitter.bytes[j];
            chunk.push_back(c);
        }
    }
}
