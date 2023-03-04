/**
 * @file aes.h
 * @author @2kai2kai2 (oritakh@gmail.com)
 *
 * C++ implementation of AES based on https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * Exposes encrypt_block() and decrypt_block()
 * Does not implement higher-level details such as chaining.
 */
#pragma once
#include "aes_constants.h"
#include <algorithm>
#include <stdexcept>

typedef unsigned char BYTE;

namespace _AES_internals {
/** Implements https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step */
template <size_t N> std::array<BYTE, N> SubBytes(const std::array<BYTE, N>& input) {
    std::array<BYTE, N> out;
#pragma clang loop vectorize(assume_safety)
    for (size_t i = 0; i < N; ++i)
        out[i] = sbox(input[i]);
    return out;
}
/** Implements an inversion of https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step */
template <size_t N> std::array<BYTE, N> InverseSubBytes(const std::array<BYTE, N>& input) {
    std::array<BYTE, N> out;
#pragma clang loop vectorize(assume_safety)
    for (size_t i = 0; i < N; ++i)
        out[i] = inv_sbox(input[i]);
    return out;
}

/** Implements https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step */
std::array<BYTE, 16> ShiftRows(const std::array<BYTE, 16>& input) {
    std::array<BYTE, 16> out;
#pragma unroll
    for (unsigned char i = 0; i < 16; ++i) {
        unsigned char r = i / 4;
        unsigned char c = i % 4;
        out[4 * r + ((4 + c + r) % 4)] = input[i];
    }
    return out;
}
/** Implements an inversion of https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step */
std::array<BYTE, 16> InverseShiftRows(const std::array<BYTE, 16>& input) {
    std::array<BYTE, 16> out;
#pragma unroll
    for (unsigned char i = 0; i < 16; ++i) {
        unsigned char r = i / 4;
        unsigned char c = i % 4;
        out[4 * r + ((4 + c - r) % 4)] = input[i];
    }
    return out;
}

/** Implements https://en.wikipedia.org/wiki/Rijndael_MixColumns */
std::array<BYTE, 16> MixColumns(const std::array<BYTE, 16>& input) {
    std::array<BYTE, 16> out;
#pragma unroll
    for (unsigned char i = 0; i < 4; ++i) {
        BYTE a = input[i];
        BYTE b = input[i + 4];
        BYTE c = input[i + 8];
        BYTE d = input[i + 12];

        out[i] = GF_m(a, 2) ^ GF_m(b, 3) ^ c ^ d;
        out[i + 4] = a ^ GF_m(b, 2) ^ GF_m(c, 3) ^ d;
        out[i + 8] = a ^ b ^ GF_m(c, 2) ^ GF_m(d, 3);
        out[i + 12] = GF_m(a, 3) ^ b ^ c ^ GF_m(d, 2);
    }
    return out;
}
/** Implements an inversion of https://en.wikipedia.org/wiki/Rijndael_MixColumns */
std::array<BYTE, 16> InverseMixColumns(const std::array<BYTE, 16>& input) {
    std::array<BYTE, 16> out;
#pragma unroll
    for (unsigned char i = 0; i < 4; ++i) {
        BYTE a = input[i];
        BYTE b = input[i + 4];
        BYTE c = input[i + 8];
        BYTE d = input[i + 12];

        out[i] = GF_m(a, 14) ^ GF_m(b, 11) ^ GF_m(c, 13) ^ GF_m(d, 9);
        out[i + 4] = GF_m(a, 9) ^ GF_m(b, 14) ^ GF_m(c, 11) ^ GF_m(d, 13);
        out[i + 8] = GF_m(a, 13) ^ GF_m(b, 9) ^ GF_m(c, 14) ^ GF_m(d, 11);
        out[i + 12] = GF_m(a, 11) ^ GF_m(b, 13) ^ GF_m(c, 9) ^ GF_m(d, 14);
    }
    return out;
}

/** Implements (inversion is the same) https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey*/
std::array<BYTE, 16> AddRoundKey(const std::array<BYTE, 16>& input, const std::array<BYTE, 16>& roundkey) {
    std::array<BYTE, 16> out;
#pragma unroll
    for (unsigned char i = 0; i < 16; ++i) {
        out[i] = input[i] ^ roundkey[i];
    }
    return out;
}

/**
 * Implementation based on https://en.wikipedia.org/wiki/AES_key_schedule#The_key_schedule
 */
class AESKeyScheduler {
    std::array<BYTE, 16 * 15> W;

public:
    AESKeyScheduler(const std::array<BYTE, 32>& key) {
        for (unsigned int i = 0; i < 16 * 15; ++i) {
            unsigned int w = i / 4;
            unsigned char b = i % 4;
            if (w < 8) {
                W[i] = key[i];
            } else if (w % 8 == 0) {
                W[i] = W[i - 32] ^ sbox(W[(w - 1) * 4 + (b + 1) % 4]) ^ _rcon[w / 8][b];
            } else if (w % 8 == 4) {
                W[i] = W[i - 32] ^ sbox(W[i - 4]);
            } else {
                W[i] = W[i - 32] ^ W[i - 4];
            }
        }
    }

    /**
     * @param roundnum Round number, in the range [0,15)
     *
     * @throws std::range_error - If roundnum >= 15
     */
    std::array<BYTE, 16> get(size_t roundnum) const {
        if (roundnum >= 15)
            throw std::range_error("Cannot get round key above number 14.");
        std::array<BYTE, 16> out;
        std::copy_n(W.begin() + roundnum * 16, 16, out.begin());
        return out;
    }
};
} // namespace _AES_internals

std::array<BYTE, 16> encrypt_block(const std::array<BYTE, 16>& ptext, const std::array<BYTE, 32>& key) {
    using namespace _AES_internals;
    AESKeyScheduler key_sched(key);
    std::array<BYTE, 16> text = AddRoundKey(ptext, key_sched.get(0));
    for (unsigned char i = 1; i <= 13; ++i) {
        text = SubBytes(text);
        text = ShiftRows(text);
        text = MixColumns(text);
        text = AddRoundKey(text, key_sched.get(i));
    }
    text = SubBytes(text);
    text = ShiftRows(text);
    return AddRoundKey(text, key_sched.get(14));
}

std::array<BYTE, 16> decrypt_block(const std::array<BYTE, 16>& ctext, const std::array<BYTE, 32>& key) {
    using namespace _AES_internals;
    AESKeyScheduler key_sched(key);
    std::array<BYTE, 16> text = AddRoundKey(ctext, key_sched.get(14));
    text = InverseShiftRows(text);
    text = InverseSubBytes(text);
    for (unsigned char i = 13; i >= 1; --i) {
        text = AddRoundKey(text, key_sched.get(i));
        text = InverseMixColumns(text);
        text = InverseShiftRows(text);
        text = InverseSubBytes(text);
    }
    return AddRoundKey(text, key_sched.get(0));
}