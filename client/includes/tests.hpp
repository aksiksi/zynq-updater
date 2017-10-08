#pragma once

#include "rsadriver.hpp"
#include "sha3driver.hpp"

void rsadriver_test() {
    RSADriver rsa_driver;
    
    std::cout << "Testing RSA driver.." << std::endl;

    // "Hello, world!" encrypted with D_pub
    const unsigned char cipher1[64] = {0x53,0x73,0x9b,0x8,0x68,0x57,0xaf,0x47,0x7b,0xc0,0xff,0x66,0x61,0x5e,0xfc,0x9,0x93,0xa0,0xbe,0x11,0x4,0xb3,0x44,0xba,0xc6,0x28,0x1d,0xc9,0xf8,0x4f,0x5a,0xdb,0xc0,0x69,0xd3,0xbd,0x5c,0x68,0x8e,0xca,0xb3,0x8c,0xb8,0xe1,0x3c,0x39,0x71,0x6c,0xf8,0x80,0x7a,0xb2,0xf9,0xd7,0xf1,0x32,0x2e,0x97,0x6b,0xdd,0xee,0x48,0x1e,0x53};
    std::string c1 (reinterpret_cast<const char*>(cipher1), 64);

    std::string plaintext = rsa_driver.decrypt(c1);
    std::string expected = "Hello, world!";

    if (plaintext.compare(expected) == 0)
        std::cout << "Test #1 succeeded." << std::endl;
    else {
        std::cout << "Test #1 failed." << std::endl;
        std::cout << "Result: " << plaintext << std::endl;
    }
}

void sha3driver_test() {
    SHA3Driver sha3driver;
    std::string message, expected, hash;

    std::cout << "Testing SHA-3 driver.." << std::endl;

    // Write 16 words (512 bits) to the SHA3 FIFO
    // In Python: 
    // b'EETT\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10EETT\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    message = "EETTEETT";
    hash = sha3driver.compute_hash(message);

    // df8b3ee8e455c8f7f8e693241eb696043e8bc2002ffe13391cf807e7996827694108fba2a2541aa849e5a33e8adc2ec24de2fe325ee027dbec902b1ac1682063
    expected = "df8b3ee8e455c8f7f8e693241eb696043e8bc2002ffe13391cf807e7996827694108fba2a2541aa849e5a33e8adc2ec24de2fe325ee027dbec902b1ac1682063";
    if (hash.compare(expected) == 0)
        std::cout << "Test #1 succeeeded." << std::endl;
    else {
        std::cout << "Test #1 failed." << std::endl;
        std::cout << "Hash: " << hash << std::endl;
    }
    
    // Message of 2 blocks
    // 961ddde44b61c14b9ebd0aee7c738c8b4e199e02055134bf48745ef9f08840b8f63848db59f0a3af3decd440d088cbfbf5fa8486e7dca30ca168f0e35a7f7eb0
    message = "EETTEETTEETTEETT";
    hash = sha3driver.compute_hash(message);

    expected = "961ddde44b61c14b9ebd0aee7c738c8b4e199e02055134bf48745ef9f08840b8f63848db59f0a3af3decd440d088cbfbf5fa8486e7dca30ca168f0e35a7f7eb0";
    if (hash.compare(expected) == 0)
        std::cout << "Test #2 succeeeded." << std::endl;
    else {
        std::cout << "Test #2 failed." << std::endl;
        std::cout << "Hash: " << hash << std::endl;
    }

    // Message of 4 blocks
    // add7ae1a89c2d578cb8e2f70ad088d8ef5aabdf1fdbd8c248a5e47bb73ec08b0178e82b17491d283815100d8871a567e637cbbb9f076e916c4fb543efe966a01
    message = "this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..this is a test..";
    hash = sha3driver.compute_hash(message);

    expected = "add7ae1a89c2d578cb8e2f70ad088d8ef5aabdf1fdbd8c248a5e47bb73ec08b0178e82b17491d283815100d8871a567e637cbbb9f076e916c4fb543efe966a01";
    if (hash.compare(expected) == 0)
        std::cout << "Test #3 succeeeded." << std::endl;
    else {
        std::cout << "Test #3 failed." << std::endl;
        std::cout << "** Hash: " << hash << std::endl;
        std::cout << "** Message: " << message << std::endl;
        std::cout << "** Message length: " << message.size() << std::endl;
    }
}
