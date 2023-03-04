// Partially based on a file from Kai's HW1
#pragma once
#include <array>
#include <bitset>
#include <stdexcept>
#include <random>
#include <time.h>

/**
 * Concatenates two bitsets.
 *
 * If the result's size (A + B) will be less than an unsigned long long, this will be much more efficient.
 */
template <size_t A, size_t B> std::bitset<A + B> concat_bitset(std::bitset<A> left, std::bitset<B> right) {
    if (A + B <= 8 * sizeof(unsigned long long))
        return (left.to_ullong() << B) | right.to_ullong();

    std::bitset<A + B> out;
    for (size_t i = 0; i < right.size(); ++i)
        out[i] = right[i];
    for (size_t i = 0; i < left.size(); ++i)
        out[i + right.size()] = left[i];
    return out;
}

/**
 * Concatenates several bitsets, with earlier bitsets in the input array being on the left.
 */
template <size_t M, size_t N> std::bitset<M * N> concat_bitset(const std::array<std::bitset<M>, N>& inputs) {
    std::bitset<M * N> out;
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < M; ++j) {
            out[i * M + j] = inputs[i][j];
        }
    }
    return out;
}

/**
 * Concatenates several bitsets, with earlier bitsets in the input array being on the left.
 * 
 * This overloaded version supports initializer lists.
 */
template <size_t M, size_t N> std::bitset<M * N> concat_bitset(std::bitset<M> const (&inputs)[N]) {
    std::bitset<M * N> out;
    for (size_t i = 0; i < N; ++i) {
        for (size_t j = 0; j < M; ++j) {
            out[i * M + j] = inputs[i][j];
        }
    }
    return out;
}

/**
 * Gives the left side (more significant half) of a bitset. If length is odd,
 * does not include the middle element.
 *
 * If the result's size (floor(N/2)) is less than an unsigned long long, this will be much more efficient.
 */
template <size_t N> std::bitset<N / 2> bitset_split_left(std::bitset<N> input) {
    if (N / 2 <= 8 * sizeof(unsigned long long))
        return (input >> (N - N / 2)).to_ullong();

    std::bitset<N / 2> out;
    for (size_t i = 0; i < N / 2; ++i)
        out[N - i - 1] = input[N - i - 1];
    return out;
}
/**
 * Gives the right side (less significant half) of a bitset. If length is odd,
 * includes the middle element.
 *
 * If the result's size (ceil(N/2)) is less than an unsigned long long, this will be much more efficient.
 */
template <size_t N> std::bitset<N - N / 2> bitset_split_right(std::bitset<N> input) {
    if (N - N / 2 <= 8 * sizeof(unsigned long long))
        return input.to_ullong();

    std::bitset<N - N / 2> out;
    for (size_t i = 0; i < N - N / 2; ++i)
        out[i] = input[i];
    return out;
}

/**
 * Gets a substring of a bitset.
 *
 * If beyond the right end of the bitset, values will still be returned as 0.
 *
 * @tparam L Length of output in bits
 * @tparam N Length of input bitset in bits
 * @param input Input bitset
 * @param offset Offset from left (most significant = 0) in multiples of L bits
 */
template <size_t L, size_t N> std::bitset<L> sub_bitset(const std::bitset<N>& input, size_t offset) {
    std::bitset<L> out;
    for (size_t i = 0; i < L && offset * L + i < N; i++)
        out[i] = input[offset * L + i];
    return out;
}

template <size_t L, size_t N>
    requires(N % L == 0)
std::array<std::bitset<L>, N / L> split_bitset(const std::bitset<N>& input) {
    std::array<std::bitset<L>, N / L> out;
    for (size_t i = 0; i < N / L; ++i)
        out[i] = sub_bitset<L>(input, i);
    return out;
}

/**
 * Permutes bits in the specified order from the input.
 *
 * Treats the order's first bit as the leftmost, which is the most significant
 * bit for bitsets. Order should be 1-indexed.
 */
template <size_t N, size_t M> std::bitset<M> permute_bits(std::bitset<N> input, const std::array<size_t, M>& order) {
    std::bitset<M> out;
    for (size_t i = 0; i < M; ++i) {
        if (0 >= order[i] || order[i] > N)
            throw std::out_of_range("Permutation order entries must be within the size of input "
                                    "(offsetted to 1-indexed).");
        // So bitsets have the opposite order in how they are indexed compared
        // with the convention of bit order for the permutations
        out[M - i - 1] = input[N - order[i]];
    }
    return out;
}

/**
 * Performs a circular left-shift on a bitset
 */
template <size_t N> std::bitset<N> circ_LS(std::bitset<N> input, size_t amount = 1) {
    amount %= N;
    return (input << amount) | (input >> (N - amount));
}

/**
 * Generates a random bitset of length L
 * 
 * Note that srand must be set.
 * 
 * @tparam L 
 * @return std::bitset<L> 
 */
template <size_t L> std::bitset<L> rand_bitset() {
    std::bitset<L> out;
    #if RAND_MAX == INT32_MAX
    for (size_t i = 0; i < L; i += 31) {
        out <<= 31;
        out |= std::bitset<L>(rand());
    }
    #else
    for (size_t i = 0; i < L; ++i)
        out[i] = rand() % 2;
    #endif
    return out;
}