#include <iostream>
#include <string>
#include <fstream>

#define ASIO_STANDALONE // Do not use Boost
#include "asio.hpp"

#include "protocol.pb.h" // protobuf message headers

#include "sha3driver.hpp"
#include "rsadriver.hpp"
#include "tests.hpp"

#define DEBUG

using asio::ip::tcp;

// Socket params
const std::string SERVER_HOST = "127.0.0.1";
const uint32_t PORT = 8080;

// Protocol params
const uint32_t NUM_ORGS = 2;
const uint32_t VERSION = 1;
const uint32_t ID = 34567154;
const char ERR_MSG[1] = {0xFF};

enum Org {
    GU,
    GC
};

void close_socket(tcp::socket& socket) {
    if (socket.is_open())
        socket.close();
}

void send_update_check(tcp::socket& socket) {
    /**
     * Send update check to server and return new update version.
     */
    std::string data;
    
    UpdateCheck uc;
    uc.set_v(VERSION);
    uc.set_id(ID);
    uc.SerializeToString(data);
    
    socket.send(data);
}

bool receive_image(tcp::socket& socket, uint32_t image_size) {
    // Open output file for received image
    std::ofstream out_file ("image.bin", std::ios::binary | std::ios::out);

    // Allocate buffer of 4 KB
    std::vector<uint8_t> buf (4096);

    uint32_t read = 0;

    // Keep reading while data available
    while (read < image_size) {
        if ((read + buf.size()) > image_size) {
            buf.resize(image_size - read);
        }

        socket.receive(asio::buffer(buf));
        out_file.write(buf.data(), buf.size());
    }

    out_file.close();
}

bool run_protocol(tcp::socket& socket, Org org) {
    bool valid;
    std::string data;
    data.reserve(512);
    
    std::vector<uint8_t> buf (512);

    // Store incoming M1 in 512 byte receive buffer
    socket.receive(asio::buffer(buf));
    data = std::string(buf.begin(), buf.end());

    // Version number is current; stop
    if (data.size() == 1 & data.at(0) == 0xFF) {
        std::cout << "Version number is current; no need to continue." << std::endl;
        return false;
    }
    
    // Parse M1 using protobuf
    M1 m1;
    valid = m1.ParseFromString(data);

    if (!valid) {
        std::cout << "Error parsing M1 from: " << org << std::endl;
        return false;
    }

    #ifndef DEBUG
        RSADriver rsadriver;
        data = rsadriver.decrypt(m1.oc());
    #else
        data = m1.oc();
    #endif

    // Parse OrgChallenge embedded in M1
    OrgChallenge oc;
    valid = oc.ParseFromString(data);
    if (!valid) {
        std::cout << "Error parsing OrgChallenge from: " << org << std::endl;
        return false;
    }

    const uint32_t ng = oc.ng();

    // Construct DeviceChallenge for org
    DeviceChallenge dc;
    dc.set_id(ID);
    dc.set_ng(ng);

    const uint32_t nd = ng >> 1;
    dc.set_nd(nd); // Generate a "random" nonce
    
    dc.SerializeToString(data);

    #ifndef DEBUG
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
    m2.SerializeToString(data);

    // Send back to org
    socket.send(data);

    // Get final reply from org as M3
    socket.receive(asio::buffer(buf));
    data = std::string(buf.begin(), buf.end());

    M3 m3;
    valid = m3.ParseFromString(data);

    if (!valid) {
        std::cout << "Error parsing M3 from: " << org << std::endl;
        return false;
    }

    #ifndef DEBUG
        data = rsadriver.decrypt(m3.or());
    #else
        data = m3.or();
    #endif

    if (org == Org::GU) {
        // Parse OrgResponse
        UpdatingOrgResponse ur;
        valid = ur.ParseFromString(data);

        if (!valid) {
            std::cout << "Error parsing OrgResponse from: " << org << std::endl;
            return false;
        }

        // Check nonce sent from org
        if (ur.nd() != nd) {
            std::cout << "Organization " << org << " authentication failed!";
            return false;
        }

        // Get image length
        socket.receive(asio::buffer(buf));
        data = std::string(buf.begin(), buf.end());
        
        UpdateImage ui;
        ui.ParseFromString(data);
        uint32_t image_size = ui.size();

        receive_image(socket, image_size);
    }

    return true;
}

int main(int argc, char** argv) {
    try {
        asio::io_service io_service;
        
        tcp::socket socket (io_service);
        tcp::resolver resolver (io_service);
        asio::connect (socket, resolver.resolve({SERVER_HOST, PORT}));

        // Send update check to server
        send_update_check(socket);

        // Run protocol for GU
        bool success = run_protocol(socket, Org::GU);
        
        // Run protocol for all GC,i
        if (success) {
            for (int i = 0; i < NUM_ORGS-1; i++) {
                if (!run_protocol(socket, Org::GC)) {
                    success = false;
                    break;
                }
            }
        }

        socket.close();

        if (success)
            std::cout << "Protocol completed successfully!" << std::endl;

    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
