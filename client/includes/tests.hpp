#include "rsadriver.hpp"
#include "sha3driver.hpp"

void rsadriver_test() {
    // TODO
    std::cout << "Testing RSA driver.." << std::endl;
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