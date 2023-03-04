/**
 * @file aes.h
 * @author @2kai2kai2 (oritakh@gmail.com)
 *
 * C++ implementation of AES based on https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
 * Exposes encrypt_block() and decrypt_block()
 * Does not implement higher-level details such as chaining.
 */
#include "aes_constants.h"
#include "lib_bitset.h"
#include <bitset>
#include <stdexcept>

namespace _AES_internals {
/** Implements https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step */
template <size_t N>
    requires(N % 8 == 0)
std::bitset<N> SubBytes(const std::bitset<N>& input) {
    std::array<std::bitset<8>, N / 8> bytes = split_bitset<8>(input);
    for (size_t i = 0; i < N / 8; ++i)
        bytes[i] = sbox(bytes[i]);
    return concat_bitset(bytes);
}
/** Implements an inversion of https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step */
template <size_t N>
    requires(N % 8 == 0)
std::bitset<N> InverseSubBytes(const std::bitset<N>& input) {
    std::array<std::bitset<8>, N / 8> bytes = split_bitset<8>(input);
    for (size_t i = 0; i < N / 8; ++i)
        bytes[i] = inv_sbox(bytes[i]);
    return concat_bitset(bytes);
}

/** Implements https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step */
std::bitset<128> ShiftRows(const std::bitset<128>& input) {
    std::array<std::bitset<32>, 4> rows = split_bitset<32>(input);
    rows[1] = circ_LS(rows[1], 8);
    rows[2] = circ_LS(rows[2], 16);
    rows[3] = circ_LS(rows[3], 24);
    return concat_bitset(rows);
}
/** Implements an inversion of https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step */
std::bitset<128> InverseShiftRows(const std::bitset<128>& input) {
    std::array<std::bitset<32>, 4> rows = split_bitset<32>(input);
    rows[1] = circ_LS(rows[1], 24);
    rows[2] = circ_LS(rows[2], 16);
    rows[3] = circ_LS(rows[3], 8);
    return concat_bitset(rows);
}

/** Implements https://en.wikipedia.org/wiki/Rijndael_MixColumns */
std::bitset<128> MixColumns(const std::bitset<128>& input) {
    std::array<std::bitset<8>, 16> bytes = split_bitset<8>(input);
    for (unsigned char i = 0; i < 4; ++i) {
        std::bitset<8> a = bytes[i];
        std::bitset<8> b = bytes[i + 4];
        std::bitset<8> c = bytes[i + 8];
        std::bitset<8> d = bytes[i + 12];

        bytes[i] = GF_m(a, 2) ^ GF_m(b, 3) ^ c ^ d;
        bytes[i + 4] = a ^ GF_m(b, 2) ^ GF_m(c, 3) ^ d;
        bytes[i + 8] = a ^ b ^ GF_m(c, 2) ^ GF_m(d, 3);
        bytes[i + 12] = GF_m(a, 3) ^ b ^ c ^ GF_m(d, 2);
    }
    return concat_bitset(bytes);
}
/** Implements an inversion of https://en.wikipedia.org/wiki/Rijndael_MixColumns */
std::bitset<128> InverseMixColumns(const std::bitset<128>& input) {
    std::array<std::bitset<8>, 16> bytes = split_bitset<8>(input);
    for (unsigned char i = 0; i < 4; ++i) {
        std::bitset<8> a = bytes[i];
        std::bitset<8> b = bytes[i + 4];
        std::bitset<8> c = bytes[i + 8];
        std::bitset<8> d = bytes[i + 12];

        bytes[i] = GF_m(a, 14) ^ GF_m(b, 11) ^ GF_m(c, 13) ^ GF_m(d, 9);
        bytes[i + 4] = GF_m(a, 9) ^ GF_m(b, 14) ^ GF_m(c, 11) ^ GF_m(d, 13);
        bytes[i + 8] = GF_m(a, 13) ^ GF_m(b, 9) ^ GF_m(c, 14) ^ GF_m(d, 11);
        bytes[i + 12] = GF_m(a, 11) ^ GF_m(b, 13) ^ GF_m(c, 9) ^ GF_m(d, 14);
    }
    return concat_bitset(bytes);
}

/** Implements (inversion is the same) https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey*/
std::bitset<128> AddRoundKey(const std::bitset<128>& input, const std::bitset<128>& roundkey) {
    return input ^ roundkey;
}

/**
 * Implementation based on https://en.wikipedia.org/wiki/AES_key_schedule#The_key_schedule
 */
class AESKeyScheduler {
    static std::bitset<32> RotWord(std::bitset<32> input) { return circ_LS(input, 8); }

    std::array<std::bitset<32>, 4 * 15> W;

public:
    AESKeyScheduler(const std::bitset<256>& key) {
        for (size_t i = 0; i < 4 * 15; ++i) {
            if (i < 8)
                W[i] = sub_bitset<32>(key, i);
            else if (i % 8 == 0)
                W[i] = W[i - 8] ^ SubBytes(RotWord(W[i - 1])) ^ _rcon[i / 8];
            else if (i % 8 == 4)
                W[i] = W[i - 8] ^ SubBytes(W[i - 1]);
            else
                W[i] = W[i - 8] ^ W[i - 1];
        }
    }

    /**
     * @param roundnum Round number, in the range [0,15)
     *
     * @throws std::range_error - If roundnum >= 15
     */
    std::bitset<128> get(size_t roundnum) const {
        if (roundnum >= 15)
            throw std::range_error("Cannot get round key above number 14.");
        return concat_bitset({W[roundnum * 4], W[roundnum * 4 + 1], W[roundnum * 4 + 2], W[roundnum * 4 + 3]});
    }
};
} // namespace _AES_internals

std::bitset<128> encrypt_block(std::bitset<128> ptext, const std::bitset<256>& key) {
    using namespace _AES_internals;
    AESKeyScheduler key_sched(key);
    std::bitset<128> text = AddRoundKey(ptext, key_sched.get(0));
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

std::bitset<128> decrypt_block(const std::bitset<128>& ctext, const std::bitset<256>& key) {
    using namespace _AES_internals;
    AESKeyScheduler key_sched(key);
    std::bitset<128> text = AddRoundKey(ctext, key_sched.get(14));
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