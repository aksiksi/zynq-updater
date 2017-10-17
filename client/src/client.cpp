#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstdlib>

#define ASIO_STANDALONE // Do not use Boost
#include "asio.hpp"

#include "protocol.pb.h" // protobuf message headers

#include "sha3driver.hpp"
#include "rsadriver.hpp"
#include "utils.hpp"

using asio::ip::tcp;

// Protocol params
const uint32_t NUM_ORGS = 2;
const uint32_t VERSION = 1;
const uint32_t ID = 34567154;
const char* IMAGE_PATH = "image.bin";
const char* DECRYPTED_IMAGE_PATH = "decrypted_image.bin";

#define DEBUG // Print debug messages
#define ENCRYPT // If defined, protocol is encrypted

enum Org {
    GU,
    GC
};

void set_random_seed() {
    /**
     * Gets a random 32-bit seed value from /dev/urandom on Linux and then
     * sets it globally.
     */
    std::ifstream random ("/dev/urandom", std::ios::binary | std::ios::in);
    uint32_t seed;
    random.read(reinterpret_cast<char *>(&seed), sizeof seed);
    random.close();
    std::srand(seed);
}

void print_binary_string(std::string& str) {
    for (int i = 0; i < str.size(); i++)
        std::cout << (int)str.at(i) << " ";

    std::cout << std::endl;
}

void close_socket(tcp::socket& socket) {
    if (socket.is_open())
        socket.close();
}

struct ImageHeader {
    // Field sizes
    uint32_t s1, s2, s3;

    // SHA3 hash
    std::string hash;
} image_header;

void send_update_check(tcp::socket& socket) {
    /**
     * Send update check to server and return new update version.
     */
    std::string data;
    
    UpdateCheck uc;
    uc.set_v(VERSION);
    uc.set_id(ID);
    uc.SerializeToString(&data);
    
    socket.send(asio::buffer(data));
}

void receive_image(tcp::socket& socket, uint32_t image_size) {
    // Open output file for received image
    std::ofstream out_file (IMAGE_PATH, std::ios::binary | std::ios::out);

    // Allocate buffer of 4 KB
    std::vector<uint8_t> buf (4096);

    // Bytes read from socket
    size_t len;

    // Total bytes read
    uint32_t total_read = 0;

    // Keep reading while data available
    while (total_read < image_size) {
        len = socket.receive(asio::buffer(buf));
        out_file.write(reinterpret_cast<char *>(buf.data()), len);

        total_read += len;
    }

    // Done!
    socket.send(asio::buffer("OK"));

    out_file.close();
}

bool run_protocol(tcp::socket& socket, Org org, std::string& hash) {
    bool valid;
    
    // Sets a global random seed from /dev/urandom
    set_random_seed();
    
    // Receive buffers
    std::string data;
    data.reserve(512);

    size_t len;
    std::vector<uint8_t> buf (512);

    // Store incoming M1 in 512 byte receive buffer
    len = socket.receive(asio::buffer(buf));
    data = std::string(buf.begin(), buf.begin() + len);
    
    // Parse M1 using protobuf
    M1 m1;
    valid = m1.ParseFromString(data);

    if (!valid) {
        print_binary_string(data);
        std::cout << "Error parsing M1 from: " << org << std::endl;
        return false;
    }

    #ifdef ENCRYPT
        RSADriver rsadriver;
        data = rsadriver.decrypt(m1.oc());
    #else
        data = m1.oc();
    #endif

    // Parse OrgChallenge embedded in M1
    OrgChallenge oc;
    valid = oc.ParseFromString(data);
    if (!valid) {
        print_binary_string(data);
        std::cout << std::endl << "Error parsing OrgChallenge from: " << org << std::endl;
        return false;
    }

    const uint32_t ng = oc.ng();

    // Construct DeviceChallenge for org
    DeviceChallenge dc;
    dc.set_id(ID);
    dc.set_ng(ng);
    
    // Generate a random device nonce, N_D
    const uint32_t nd = std::rand();
    dc.set_nd(nd);
    
    dc.SerializeToString(&data);

    #ifdef ENCRYPT
        // Determine pub key to use for encryption
        RSAKey key;
        if (org == Org::GU)
            key = RSAKey::GU_PUB;
        else if (org == Org::GC)
            key = RSAKey::GC_PUB;

        data = rsadriver.encrypt(data, key);
    #endif

    M2 m2;
    m2.set_dc(data);
    m2.SerializeToString(&data);

    // Send back to org
    socket.send(asio::buffer(data));

    // Get final reply from org as M3
    len = socket.receive(asio::buffer(buf));
    data = std::string(buf.begin(), buf.begin() + len);

    M3 m3;
    valid = m3.ParseFromString(data);

    if (!valid) {
        print_binary_string(data);
        std::cout << "Error parsing M3 from: " << org << std::endl;
        return false;
    }

    #ifdef ENCRYPT
        data = rsadriver.decrypt(m3.or_());
    #else
        data = m3.or_();
    #endif

    // Parse OrgResponse
    OrgResponse ur;
    valid = ur.ParseFromString(data);

    if (!valid) {
        print_binary_string(data);
        std::cout << "Error parsing OrgResponse from: " << org << std::endl;
        return false;
    }

    // Check nonce sent from org
    if (ur.nd() != nd) {
        std::cout << "Organization " << org << " authentication failed!";
        return false;
    }

    if (org == Org::GU) {
        // Get image length
        len = socket.receive(asio::buffer(buf));
        data = std::string(buf.begin(), buf.begin() + len);
        
        UpdateImage ui;
        ui.ParseFromString(data);
        uint32_t image_size = ui.size();

        // Tell server to start sending the update image
        socket.send(asio::buffer("OK"));

        // Receive the update image and write to IMAGE_PATH on disk
        receive_image(socket, image_size);
    }
    
    else if (org == Org::GC) {
        // Retrieve hash from the org
        hash = ur.hc();
    }

    return true;
}

void read_image_header(const char* path) {
    // NOTE: function assumes image has exactly 3 fields!
    // i.e., BOOT.bin, image.ub, and application (in that order)
    std::ifstream image (path, std::ios::binary | std::ios::in);
    uint32_t seek_pos = 1; // Skip length byte at start of file
    
    image.read(reinterpret_cast<char *>(&image_header.s1), 4);
    
    seek_pos += 4;
    image.seekg(seek_pos);
    image.read(reinterpret_cast<char *>(&image_header.s2), 4);
    
    seek_pos += 4;
    image.seekg(seek_pos);
    image.read(reinterpret_cast<char *>(&image_header.s3), 4);
    
    seek_pos += 4;
    
    // Read in hash byte-by-byte
    uint8_t byte;
    
    for (int i = 0; i < HASH_SIZE; i++) {
        image.seekg(seek_pos + i);
        image.read(reinterpret_cast<char *>(&byte), 1);
        image_header.hash.push_back(byte);
    }

    image.close();
}

std::streampos get_file_size(const char* path) {
    std::streampos fsize = 0;
    std::ifstream file(path, std::ios::binary);

    fsize = file.tellg();
    file.seekg(0, std::ios::end);
    fsize = file.tellg() - fsize;
    file.close();

    return fsize;
}

bool decrypt_image() {
    auto image_size = get_file_size(IMAGE_PATH);
    
    // Ciphertext
    std::string ciphertext;
    ciphertext.reserve(image_size);

    // Read entire update image into memory
    std::ifstream image (IMAGE_PATH, std::ios::binary | std::ios::in);
    std::ostringstream oss;
    oss << image.rdbuf();
    ciphertext = oss.str();
    image.close();

    // Decrypt the image
    #ifdef ENCRYPT
        std::cout << "Decrypting the update image: Size = " << image_size << std::endl;
        RSADriver rsadriver;
        std::string plaintext = rsadriver.decrypt(ciphertext);
    #else
        std::string plaintext = ciphertext;
    #endif

    // Write to disk
    std::ofstream decrypted_image (DECRYPTED_IMAGE_PATH, std::ios::binary | std::ios::out);
    decrypted_image.write(plaintext.data(), plaintext.size());

    decrypted_image.close();

    return true;
}

std::string compute_image_hash() {
    // NOTE: this function assumes 3 fields in the image header
    
    // Read in image header
    read_image_header(DECRYPTED_IMAGE_PATH);

    // Open image and seek to correct start position in file
    std::ifstream image (DECRYPTED_IMAGE_PATH, std::ios::binary | std::ios::in);
    image.seekg(1 + 12 + HASH_SIZE); // See server/update_image.py for header structure

    // Read out the file contents for hashing
    std::ostringstream oss;
    oss << image.rdbuf();
    std::string content = oss.str();
    image.close();

    SHA3Driver driver;
    
    // Compute hash
    return driver.compute_hash(content, false);
}

bool validate_hashes(std::vector<std::string>& hashes) {
    std::string hash = compute_image_hash();

    if (hash.compare(image_header.hash) != 0) {
        std::cout << "Header and content hashes are different!" << std::endl;
    }

    // Check confirming hashes against update image hash
    for (std::string& h: hashes) {
        if (h.compare(image_header.hash) != 0) {
            std::cout << "Hash mismatch detected!" << std::endl;

            #ifdef DEBUG
                // Print out all 3 hashes
                for (int i = 0; i < HASH_SIZE; i++)
                    std::cout << std::hex << (int)hash.at(i) << " ";
                
                std::cout << std::endl;
        
                for (int i = 0; i < HASH_SIZE; i++)
                    std::cout << std::hex << (int)hashes[0].at(i) << " ";
            
                std::cout << std::endl;
        
                for (int i = 0; i < HASH_SIZE; i++)
                    std::cout << std::hex << (int)image_header.hash.at(i) << " ";
            
                std::cout << std::endl;
            #endif

            return false;
        }
    }

    return true;
}

void execute_update() {
    // Extract image into seperate files (BOOT.bin, image.ub, application)

    // Back up old files on SD card (shell?)
    
    // Move new files to SD card (shell?)
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cout << "Usage: zynq-updater <ip> <port>" << std::endl;
        return 0;
    }

    // Get host and port from cmdline args
    const char* server_host = argv[1];
    const uint32_t port = std::stoi(argv[2], nullptr);

    try {
        asio::io_service io_service;
        asio::ip::tcp::endpoint endpoint (asio::ip::address::from_string(server_host), port);
        
        tcp::socket socket (io_service);
        socket.connect(endpoint);

        // Send update check to server
        send_update_check(socket);

        // Variables to store hashes received from orgs
        std::vector<std::string> hashes;
        std::string hash;
        hash.reserve(64);

        // Start timing the protocol
        const auto start = std::chrono::high_resolution_clock::now();

        // Run protocol for GU
        bool success = run_protocol(socket, Org::GU, hash);
        
        // Run protocol for all GC,i
        if (success) {
            for (int i = 0; i < NUM_ORGS-1; i++) {
                // Returns the hash sent by G_C,i
                success = run_protocol(socket, Org::GC, hash);
                hashes.push_back(hash);
                
                // Stop checking if one org fails
                if (!success) {
                    std::cout << "Confirming org #" << i << " failed the protocol!" << std::endl;
                }
            }
        }

        socket.close();

        // Auth completed
        const auto t2 = std::chrono::high_resolution_clock::now();

        if (success) {
            const auto auth_time = std::chrono::duration_cast<std::chrono::microseconds>(t2 - start).count() / 1000000.0;
            std::cout << "Authentication completed successfully in " << auth_time << std::endl;

            // Decrypt the update image (if applicable)
            decrypt_image();

            const auto t3 = std::chrono::high_resolution_clock::now();
            const auto dec_time = std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count() / 1000000.0;
            std::cout << "Image decrypted in " << dec_time << std::endl;
        }

        const auto t3 = std::chrono::high_resolution_clock::now();

        // Check all received hashes
        if (success && hashes.size() == NUM_ORGS-1 && validate_hashes(hashes)) {
            const auto t4 = std::chrono::high_resolution_clock::now();
            const auto hash_time = std::chrono::duration_cast<std::chrono::microseconds>(t4 - t3).count() / 1000000.0;
            std::cout << "Hash validation completed in " << hash_time << std::endl;

            std::cout << "Executing update..." << std::endl;
            execute_update();
            
            // Compute time elapsed for current run
            const auto end = std::chrono::high_resolution_clock::now();
            const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            
            std::cout << std::dec << "Protocol completed successfully in " << (duration/1000000.0) << " seconds and all hashes match!" << std::endl;
        } else {
            std::cout << "Protocol failed!" << std::endl;
        }
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
