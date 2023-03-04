/**
 * @file aes_test.cpp
 * Used for testing aes.h
 * Pure c++
 */
#include "aes.h"
#include <iostream>
#include <time.h>

int main() {
    std::srand(time(NULL));

    std::cout << "Testing SubBytes / InverseSubBytes:" << std::endl;
    size_t passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::bitset<128> original = rand_bitset<128>();
        std::bitset<128> modified = _AES_internals::SubBytes(original);
        std::bitset<128> inverted = _AES_internals::InverseSubBytes(modified);

        if (original != inverted) {
            std::cout << "ERROR: SubBytes mismatch: " << original << " => " << modified << " =>" << inverted
                      << std::endl;
        } else {
            ++passed;
        }
    }
    std::cout << passed << "/1000 Passed." << std::endl;

    std::cout << "Testing ShiftRows / InverseShiftRows:" << std::endl;
    passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::bitset<128> original = rand_bitset<128>();
        std::bitset<128> modified = _AES_internals::ShiftRows(original);
        std::bitset<128> inverted = _AES_internals::InverseShiftRows(modified);

        if (original != inverted) {
            std::cout << "ERROR: ShiftRows mismatch: " << original << " => " << modified << " =>" << inverted
                      << std::endl;
        } else {
            ++passed;
        }
    }
    std::cout << passed << "/1000 Passed." << std::endl;

    std::cout << "Testing MixColumns / InverseMixColumns:" << std::endl;
    passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::bitset<128> original = rand_bitset<128>();
        std::bitset<128> modified = _AES_internals::MixColumns(original);
        std::bitset<128> inverted = _AES_internals::InverseMixColumns(modified);

        if (original != inverted) {
            std::cout << "ERROR: MixColumns mismatch: " << original << " => " << modified << " =>" << inverted
                      << std::endl;
        } else {
            ++passed;
        }
    }
    std::cout << passed << "/1000 Passed." << std::endl;

    std::cout << "Testing encrypt_block / decrypt_block:" << std::endl;
    passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::bitset<256> key = rand_bitset<256>();
        std::bitset<128> original = rand_bitset<128>();
        std::bitset<128> modified = encrypt_block(original, key);
        std::bitset<128> inverted = decrypt_block(modified, key);

        if (original != inverted) {
            std::cout << "ERROR: block encryption/decryption mismatch: " << original << " => " << modified << " =>" << inverted
                      << std::endl;
        } else {
            ++passed;
        }
    }
    std::cout << passed << "/1000 Passed." << std::endl;
}