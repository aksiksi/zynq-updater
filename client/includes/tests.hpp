#pragma once

#include "rsadriver.hpp"
#include "sha3driver.hpp"

void rsadriver_test() {
    RSADriver rsa_driver;
    
    std::cout << "Testing RSA driver.." << std::endl;

    // "Hello, world!" encrypted with D_pub
    const unsigned char cipher1[64] = {0x5a,0xeb,0x41,0x45,0x33,0x53,0xcc,0x5e,0xa7,0x85,0xc8,0xcd,0x51,0x1b,0x2f,0xf0,0x6e,0xd4,0xa0,0x94,0x38,0x15,0x3f,0xe5,0xa5,0x71,0x8b,0xba,0x6e,0x82,0xa2,0x2,0xc3,0xb,0x42,0x72,0x57,0x88,0xe7,0x79,0x98,0xf,0xd5,0xc2,0x6e,0x49,0xf5,0xfa,0x80,0xde,0x97,0xc8,0xfd,0xa2,0x15,0x53,0x9e,0x2c,0xe4,0x61,0xb9,0xa,0xb8,0x80};
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
    hash = sha3driver.compute_hash(message, true);

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
    hash = sha3driver.compute_hash(message, true);

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
    hash = sha3driver.compute_hash(message, true);

    expected = "add7ae1a89c2d578cb8e2f70ad088d8ef5aabdf1fdbd8c248a5e47bb73ec08b0178e82b17491d283815100d8871a567e637cbbb9f076e916c4fb543efe966a01";
    if (hash.compare(expected) == 0)
        std::cout << "Test #3 succeeeded." << std::endl;
    else {
        std::cout << "Test #3 failed." << std::endl;
        std::cout << "** Hash: " << hash << std::endl;
        std::cout << "** Message: " << message << std::endl;
        std::cout << "** Message length: " << message.size() << std::endl;
    }

    // Short message of 12 bytes which will be padded with 0xFF
    message = "Hello, world!";
    hash = sha3driver.compute_hash(message, true);

    expected = "6dc1540d55e973fc207aa8cb31ae9f6d19be3bd38100b437a37768df41a958aeb6ae0beb6485e22b2b308506899be1b1c5aefa14da1321f7dc5287ba77e2dbf0";
    if (hash.compare(expected) == 0)
        std::cout << "Test #4 succeeeded." << std::endl;
    else {
        std::cout << "Test #4 failed." << std::endl;
        std::cout << "** Hash: " << hash << std::endl;
        std::cout << "** Message: " << message << std::endl;
        std::cout << "** Message length: " << message.size() << std::endl;
    }
}
