#include <iostream>
#include <string>

#define ASIO_STANDALONE // Do not use Boost
#include "asio.hpp"

#include "protocol.pb.h" // protobuf message headers

#include "client.hpp"
#include "sha3driver.hpp"

using asio::ip::tcp;

bool update_check(std::string& serialized) {
    // Send update check
    uint32_t V = 150;
    uint32_t ID = 100031031;

    UpdateCheck uc;
    uc.set_v(V);
    uc.set_id(ID);
    
    return uc.SerializeToString(&serialized);
}

int main(int argc, char** argv) {
    try {
        asio::io_service io_service;
        
        tcp::socket socket (io_service);
        tcp::resolver resolver (io_service);
        asio::connect (socket, resolver.resolve({"127.0.01", "8080"}));

        // Send serialized message to server
        std::string response;
        bool r = update_check(response);

        socket.send(asio::buffer(response, response.size()));

        // Read in reply
        std::vector<uint8_t> reply (128);
        socket.receive(asio::buffer(reply));

        std::string data (reply.begin(), reply.end());

        std::cout << "Reply is: " << data << std::endl;
    } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
