/**
 * @file aes_test.cpp
 * Used for testing aes.h
 * Pure c++
 */
#include "aes.h"
#include <iostream>
#include <time.h>

template <size_t N> std::array<BYTE, N> rand_bytes() {
    std::array<BYTE, N> out;
    for (size_t i = 0; i < N; ++i)
        out[i] = rand();
    return out;
}

int main() {
    std::srand(time(NULL));

    std::cout << "Testing SubBytes / InverseSubBytes:" << std::endl;
    size_t passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::array<BYTE, 16> original = rand_bytes<16>();
        std::array<BYTE, 16> modified = _AES_internals::SubBytes(original);
        std::array<BYTE, 16> inverted = _AES_internals::InverseSubBytes(modified);

        if (original == inverted)
            ++passed;
    }
    std::cout << passed << "/1000 Passed." << std::endl;

    std::cout << "Testing ShiftRows / InverseShiftRows:" << std::endl;
    passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::array<BYTE, 16> original = rand_bytes<16>();
        std::array<BYTE, 16> modified = _AES_internals::ShiftRows(original);
        std::array<BYTE, 16> inverted = _AES_internals::InverseShiftRows(modified);

        if (original == inverted)
            ++passed;
    }
    std::cout << passed << "/1000 Passed." << std::endl;

    std::cout << "Testing MixColumns / InverseMixColumns:" << std::endl;
    passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::array<BYTE, 16> original = rand_bytes<16>();
        std::array<BYTE, 16> modified = _AES_internals::MixColumns(original);
        std::array<BYTE, 16> inverted = _AES_internals::InverseMixColumns(modified);

        if (original == inverted)
            ++passed;
    }
    std::cout << passed << "/1000 Passed." << std::endl;

    std::cout << "Testing encrypt_block / decrypt_block:" << std::endl;
    passed = 0;
    for (size_t i = 0; i < 1000; ++i) {
        std::array<BYTE, 32> key = rand_bytes<32>();
        std::array<BYTE, 16> original = rand_bytes<16>();
        std::array<BYTE, 16> modified = encrypt_block(original, key);
        std::array<BYTE, 16> inverted = decrypt_block(modified, key);

        if (original == inverted)
            ++passed;
    }
    std::cout << passed << "/1000 Passed." << std::endl;
}