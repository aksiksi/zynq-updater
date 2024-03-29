#pragma once

#include "rsadriver.hpp"
#include "sha3driver.hpp"

void rsadriver_test() {
    RSADriver rsa_driver;
    std::string plaintext, expected;
    
    std::cout << "Testing RSA driver.." << std::endl;

    // "Hello, world!" encrypted with D_pub
    const unsigned char cipher1[64] = {0x5a,0xeb,0x41,0x45,0x33,0x53,0xcc,0x5e,0xa7,0x85,0xc8,0xcd,0x51,0x1b,0x2f,0xf0,0x6e,0xd4,0xa0,0x94,0x38,0x15,0x3f,0xe5,0xa5,0x71,0x8b,0xba,0x6e,0x82,0xa2,0x2,0xc3,0xb,0x42,0x72,0x57,0x88,0xe7,0x79,0x98,0xf,0xd5,0xc2,0x6e,0x49,0xf5,0xfa,0x80,0xde,0x97,0xc8,0xfd,0xa2,0x15,0x53,0x9e,0x2c,0xe4,0x61,0xb9,0xa,0xb8,0x80};
    std::string c1 (reinterpret_cast<const char*>(cipher1), 64);

    plaintext = rsa_driver.decrypt(c1);
    expected = "Hello, world!";

    if (plaintext.compare(expected) == 0)
        std::cout << "Test #1 succeeded." << std::endl;
    else {
        std::cout << "Test #1 failed." << std::endl;
        std::cout << "Result: " << plaintext << std::endl;
    }

    // Lorem ipsum text with 750 characters encrypted with D_pub
    const unsigned char cipher2[960] = {0x21,0x15,0x51,0xae,0x1e,0x2a,0x9d,0x1d,0x8,0x61,0x1d,0xad,0x9c,0x5c,0x21,0x7f,0x91,0x7,0xbb,0x2f,0xcc,0x49,0x84,0xf,0xbd,0x5c,0x2c,0x18,0x6e,0x40,0xa9,0x93,0xd,0xbe,0xd7,0xae,0x18,0xae,0x68,0x85,0x9c,0x8c,0xe8,0x83,0x3c,0x3f,0x8d,0x8a,0x92,0x4,0x5b,0x46,0xad,0xf0,0x30,0x90,0x2a,0x7a,0x92,0xf,0x55,0x22,0x4e,0x2a,0x3b,0xb4,0x5e,0x24,0x95,0xee,0x79,0xed,0x36,0x7,0x98,0x46,0xbf,0xee,0x85,0xc9,0x23,0x1f,0xf8,0x2f,0xde,0xef,0x5b,0xdf,0xa9,0xaa,0xe0,0xb9,0x66,0xb,0x4f,0xc5,0x3f,0x5a,0xc4,0xb9,0xf6,0x63,0x5c,0x48,0x20,0x3f,0x95,0x60,0xf5,0x88,0xbf,0xe,0x3e,0x33,0xc5,0x63,0x53,0x26,0x67,0x83,0x34,0x52,0xf9,0x42,0x18,0x88,0x27,0xd3,0x31,0x8,0xda,0x20,0x4,0x52,0x9b,0x25,0xd,0x24,0x1b,0x3,0x8e,0xa9,0x74,0xab,0x19,0x80,0xa2,0xbe,0x44,0x44,0x2a,0x99,0xc8,0x9c,0x65,0xdf,0x41,0xe6,0xd1,0x38,0x1a,0xfe,0x3b,0x44,0x17,0x9b,0x3b,0xd,0x78,0xb4,0x3f,0xa8,0xfc,0xd5,0x6e,0x71,0x21,0x69,0xd1,0xcd,0x1b,0x6,0xa8,0x37,0xf2,0x9c,0x9b,0xb4,0xe3,0x9b,0xed,0x3a,0x6c,0x1d,0x1e,0xb2,0x3e,0x89,0x31,0x27,0x59,0x34,0xc0,0x8b,0x36,0xaa,0x33,0x49,0xf2,0xb8,0x1d,0xe6,0x4a,0xf1,0xc8,0x20,0x72,0x5d,0xb9,0xdd,0x58,0x19,0x7b,0x7d,0xd2,0x32,0x24,0x7a,0x47,0xcf,0xa3,0xdb,0xe3,0xc2,0x2b,0x1b,0x13,0x1b,0xf4,0x6c,0x39,0x33,0x62,0x1e,0xcf,0xc9,0xb7,0x92,0x21,0xc9,0x73,0xed,0x19,0x80,0x24,0xb6,0x55,0x21,0x50,0x32,0x21,0xb1,0xac,0x63,0xf0,0xa2,0xa4,0xf2,0xae,0x31,0x4a,0xce,0x8a,0x7f,0xe0,0xba,0x71,0x54,0xda,0x8f,0x20,0x2d,0x96,0x76,0xbd,0x3b,0xc9,0x81,0x57,0x17,0x93,0x79,0x64,0xee,0x88,0xea,0x70,0x85,0x83,0xd8,0xe8,0x83,0x7f,0x3,0x5b,0xb,0x3a,0x57,0xca,0x40,0xd7,0x72,0x93,0xf3,0x13,0x29,0xb7,0xf4,0x5a,0xe,0x7b,0x9d,0x9d,0x36,0xec,0x93,0x83,0x95,0xcd,0x7e,0xa0,0x76,0x38,0x40,0x2b,0xf3,0xf3,0x43,0xb3,0xb1,0x2b,0x7e,0x74,0xf6,0x4,0xee,0x20,0xcd,0xb1,0x6e,0x75,0xa7,0x36,0x48,0x62,0xd4,0x42,0x3,0xe1,0xf6,0x7a,0xa1,0x8a,0x70,0xc8,0xe1,0x87,0x8b,0x46,0xba,0xec,0x63,0x8c,0x52,0xff,0xa3,0xed,0x2a,0xf9,0xcf,0xdc,0xd0,0xfd,0x68,0x7,0xcd,0x29,0x28,0x70,0xa7,0xc3,0xa,0x98,0x6,0x5a,0xd0,0x3b,0x35,0x6f,0xc9,0x2c,0x51,0xae,0x75,0x32,0x98,0x16,0x60,0x7e,0x55,0x39,0xa2,0xc0,0x72,0x30,0x6b,0xb,0xfc,0x70,0x58,0x3a,0x69,0xa6,0xdd,0xee,0x1d,0x9,0x28,0x96,0xe0,0x4c,0xd1,0xd8,0xb9,0x4a,0x29,0x9f,0xc7,0x80,0x76,0x4e,0x21,0xed,0xf7,0x2,0x4c,0x11,0xdd,0x77,0x6d,0x24,0xb7,0xe7,0x2c,0x30,0xc,0xd0,0xee,0xdd,0x20,0xe1,0x86,0x3f,0xc7,0x6,0xc4,0x70,0xc2,0x53,0xe,0x2f,0x25,0xa3,0x28,0x11,0xe9,0x4a,0xb2,0x28,0x27,0x47,0xf0,0x8f,0xbf,0x2,0xcf,0x14,0x4b,0x9f,0x83,0x7b,0xb2,0x25,0x12,0xd6,0xea,0x25,0x53,0xce,0x9a,0x7e,0x1b,0x33,0xdb,0xb8,0x47,0x4d,0xce,0xdf,0x5c,0x4c,0x5f,0xb,0xd1,0xdf,0xac,0xad,0x51,0xf,0xe3,0xe1,0x41,0xbb,0x5f,0xdd,0x3c,0xc0,0xf4,0x6e,0x81,0xa3,0x4e,0x3c,0x29,0x3f,0xb4,0x11,0x4,0xd6,0x6b,0xa,0x6a,0x51,0xa6,0xb1,0x6f,0x58,0xfa,0xed,0x45,0x32,0x5c,0xd1,0x62,0x7e,0x50,0xd6,0x1d,0x9c,0x7f,0xa1,0x28,0x3c,0xc8,0xb9,0x67,0x9,0x4e,0x4d,0x81,0x8f,0x6a,0xb,0x89,0xf6,0xa0,0x33,0x65,0x2b,0x6b,0xdb,0xfa,0x9c,0x26,0x9a,0xe,0x65,0xae,0x21,0xb4,0x1e,0x98,0x5f,0xb8,0x5f,0x22,0xe,0x45,0x68,0x8,0xdf,0x7d,0x6f,0xcc,0x12,0x31,0x39,0x8e,0x80,0x25,0x96,0x43,0xa2,0x28,0x45,0x3a,0xcd,0x3d,0x68,0x4b,0x2f,0xb2,0x94,0x18,0x9e,0x53,0x41,0x5a,0xb7,0xe3,0x4a,0xba,0x51,0x1f,0x99,0x6d,0x8,0x50,0xbb,0xfd,0x1b,0xdd,0xda,0xfd,0xbc,0x12,0xef,0x9a,0x57,0xfd,0xaa,0xd2,0xa1,0x33,0x99,0xe7,0x63,0xe3,0xdd,0xd6,0x1a,0xa3,0xa5,0x19,0xf,0x44,0xc8,0x3b,0x35,0xc2,0xfe,0x86,0xcc,0xbe,0x6f,0x28,0xc4,0x46,0xe,0x2f,0x77,0x87,0xbd,0x66,0xec,0x47,0xbe,0x5a,0x60,0xa4,0xf1,0xb,0x6b,0x5f,0x6d,0x9b,0x54,0x96,0x1f,0x9a,0x76,0xa,0x79,0xb7,0x6e,0x9e,0x42,0xc7,0x25,0xb3,0xab,0x6,0x17,0x3e,0x61,0x64,0x79,0x9,0xe0,0xa2,0xcb,0x35,0xc0,0xf4,0xe1,0x7d,0x2c,0xc9,0x79,0x50,0x6f,0x3b,0x1d,0x8,0xe7,0x73,0xd0,0xc9,0xd2,0x98,0xca,0x70,0x3b,0x13,0xb,0x5a,0x34,0x88,0xdc,0x1a,0x5,0xff,0x90,0xab,0x1b,0x47,0x22,0xdb,0xb2,0x56,0x99,0x1,0x7e,0x4e,0xf8,0x21,0x88,0x76,0x3b,0xd9,0x7e,0x37,0xc9,0x6d,0x6c,0xa6,0x8d,0x65,0x93,0xea,0xb4,0x22,0x13,0xa6,0x1f,0x2,0xfa,0xb7,0x3d,0x89,0x47,0xc6,0xfd,0x4e,0xa,0xd2,0xd,0x3,0x63,0xfc,0xb0,0x1c,0xd,0x5b,0x12,0xbf,0xff,0x28,0x4f,0x78,0xb5,0xa7,0x21,0xe3,0xb8,0x1e,0x83,0xbb,0x6e,0x2d,0xbb,0xb4,0x13,0xd2,0x55,0x8f,0x4f,0xf,0x99,0x92,0xe1,0x1d,0x45,0xa6,0x5,0xc4,0xdd,0x8e,0xee,0xed,0x8a,0xd2,0xa6,0x7a,0x96,0xeb,0xfe,0x6c,0x8f,0x7a,0x60,0x51,0x9c,0xd0,0xd,0xad,0xe4,0xbc,0xc6,0x6d,0x96,0x1b,0x70,0x9c,0xaf,0x30,0xc,0x44,0xc9,0x45,0xb9,0x67,0xbb,0x2c,0x52,0xb1,0x6b,0x7f,0x58,0xb,0x7,0x21,0x8f,0x56,0xae,0x7a,0xcf,0x75,0xb0,0x8b,0xa,0x7a,0xa7,0x49,0xb6,0xa4,0x65,0xb8,0xe1,0x8b,0x6a,0xf3,0x98,0x5b,0x2b,0x0,0xb1,0xf0,0x1b,0x8d,0xe6,0x7a,0x56,0xc9,0xa4,0xbb,0xd4,0x65,0x33,0x69,0x8d,0x56,0xe1,0x27,0x74,0xc6,0x5e,0xb,0xda,0x43,0x66,0x84,0x47,0x72,0x99,0xb5,0x44,0xc9,0x99,0xaa,0xe0,0x27,0xde,0xe0,0x81,0x87,0x1e,0xbc,0x4f,0x77,0x80,0x51,0xe8,0x11,0x1c,0x1a,0xc2,0x6f,0xab,0x10};
    std::string c2 (reinterpret_cast<const char*>(cipher1), 960);

    plaintext = rsa_driver.decrypt(c2);
    expected = "There are many variations of passages of Lorem Ipsum available, but the majority have suffered alteration in some form, by injected humour, or randomised words which don't look even slightly believable. If you are going to use a passage of Lorem Ipsum, you need to be sure there isn't anything embarrassing hidden in the middle of text. All the Lorem Ipsum generators on the Internet tend to repeat predefined chunks as necessary, making this the first true generator on the Internet. It uses a dictionary of over 200 Latin words, combined with a handful of model sentence structures, to generate Lorem Ipsum which looks reasonable. The generated Lorem Ipsum is therefore always free from repetition, injected humour, or non-characteristic words etc.";

    if (plaintext.compare(expected) == 0)
        std::cout << "Test #2 succeeded." << std::endl;
    else {
        std::cout << "Test #2 failed." << std::endl;
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
        std::cout << "Test #1 succeeded." << std::endl;
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
        std::cout << "Test #2 succeeded." << std::endl;
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
        std::cout << "Test #3 succeeded." << std::endl;
    else {
        std::cout << "Test #3 failed." << std::endl;
        std::cout << "** Hash: " << hash << std::endl;
        std::cout << "** Message: " << message << std::endl;
        std::cout << "** Message length: " << message.size() << std::endl;
    }

    // Short message of 12 bytes which will be internally padded with 0xFF
    message = "Hello, world!";
    hash = sha3driver.compute_hash(message, true);

    expected = "9871c9900ce0b82977447481c9ca3f99ad40b6054ae9555771dcb865fc6e2c43b10097d5078c2f9868bb0e1f90a153810718d522cc24db34e437ad732dcefa37";
    if (hash.compare(expected) == 0)
        std::cout << "Test #4 succeeded." << std::endl;
    else {
        std::cout << "Test #4 failed." << std::endl;
        std::cout << "** Hash: " << hash << std::endl;
        std::cout << "** Message: " << message << std::endl;
        std::cout << "** Message length: " << message.size() << std::endl;
    }
}
