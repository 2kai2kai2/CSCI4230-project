#include "aes.h"
#include <pybind11/pybind11.h>
#include <string>

namespace py = pybind11;

template <size_t N> std::array<BYTE, N> bytes_to_array(const py::bytes& bytes, const std::string& name) {
    std::string str = bytes; // Convert first to string
    if (str.size() != N) {
        throw std::length_error(name + " has invalid length (should be " + std::to_string(N * 8) + " bits/" +
                                std::to_string(N) + " bytes).");
    }
    std::array<BYTE, N> out;
    std::copy_n(str.begin(), N, out.begin());
    return out;
}

/**
 * @param msg A 128-bit (16-byte) plaintext block to encrypt
 * @param key A 256-bit (32-byte) symmetric key
 * @return py::bytes The cooresponding 128-bit (16-byte) ciphertext
 * @throws std::length_error if inputs are invalid
 */
py::bytes py_encrypt_block(py::bytes msg, py::bytes key) {
    std::array<BYTE, 16> msg_a = bytes_to_array<16>(msg, "Plaintext");
    std::array<BYTE, 32> key_a = bytes_to_array<32>(key, "Key");
    std::array<BYTE, 16> ctxt = encrypt_block(msg_a, key_a);
    return py::bytes((const char*)ctxt.data(), 16);
}

/**
 * @param msg A 128-bit (16-byte) ciphertext block to decrypt
 * @param key A 256-bit (32-byte) symmetric key
 * @return py::bytes The cooresponding 128-bit (16-byte) plaintext
 * @throws std::length_error if inputs are invalid
 */
py::bytes py_decrypt_block(py::bytes msg, py::bytes key) {
    std::array<BYTE, 16> msg_a = bytes_to_array<16>(msg, "Ciphertext");
    std::array<BYTE, 32> key_a = bytes_to_array<32>(key, "Key");
    std::array<BYTE, 16> ptxt = decrypt_block(msg_a, key_a);
    return py::bytes((const char*)ptxt.data(), 16);
}

/**
 * @param msg A plaintext block to encrypt, where the length is a multiple of 128 bits (16 bytes).
 * @param key A 256-bit (32-byte) symmetric key.
 * @param IV A 128-bit (16-byte) initialization vector.
 * @return py::bytes The cooresponding ciphertext of the same size as the plaintext.
 * @throws std::length_error if inputs are invalid
 */
py::bytes py_encrypt_cbc(py::bytes msg, py::bytes key, py::bytes IV) {
    std::string msg_s = msg;
    if (msg_s.size() % 16 != 0)
        throw std::length_error("Plaintext has invalid length (should be multiple of 128 bits/16 bytes).");
    std::array<BYTE, 32> key_a = bytes_to_array<32>(key, "Key");
    std::array<BYTE, 16> IV_a = bytes_to_array<16>(IV, "Initialization Vector");

    std::string out(msg_s.size(), 0);
    for (size_t i = 0; i < msg_s.size(); i += 16) {
        std::array<BYTE, 16> block;
        for (unsigned char j = 0; j < 16; ++j)
            block[j] = msg_s[i + j] ^ IV_a[j];
        block = encrypt_block(block, key_a);
        IV_a = block;
        std::copy_n(block.begin(), 16, out.begin() + i);
    }
    return py::bytes(out);
}

/**
 * @param msg A ciphertext block to decrypt, where the length is a multiple of 128 bits (16 bytes).
 * @param key A 256-bit (32-byte) symmetric key
 * @param IV The 128-bit (16-byte) initialization vector used during encryption.
 * @return py::bytes The cooresponding plaintext of the same size as the ciphertext.
 * @throws std::length_error if inputs are invalid
 */
py::bytes py_decrypt_cbc(py::bytes msg, py::bytes key, py::bytes IV) {
    std::string msg_s = msg;
    if (msg_s.size() % 16 != 0)
        throw std::length_error("Ciphertext has invalid length (should be multiple of 128 bits/16 bytes).");
    std::array<BYTE, 32> key_a = bytes_to_array<32>(key, "Key");
    std::array<BYTE, 16> IV_a = bytes_to_array<16>(IV, "Initialization Vector");

    std::string out(msg_s.size(), 0);
    for (size_t i = 0; i < msg_s.size(); i += 16) {
        std::array<BYTE, 16> cblock;
        std::copy_n(msg_s.begin() + i, 16, cblock.begin());
        std::array<BYTE, 16> pblock = decrypt_block(cblock, key_a);
        for (unsigned char j = 0; j < 16; ++j)
            out[i + j] = pblock[j] ^ IV_a[j];
        IV_a = cblock;
    }
    return py::bytes(out);
}

PYBIND11_MODULE(_cpplib, m) {
    m.doc() = "c++ extension library";
    m.def("encrypt_block", &py_encrypt_block, py::arg("msg"), py::arg("key"));
    m.def("decrypt_block", &py_decrypt_block, py::arg("msg"), py::arg("key"));
    m.def("encrypt_cbc", &py_encrypt_cbc, py::arg("msg"), py::arg("key"), py::arg("IV"));
    m.def("decrypt_cbc", &py_decrypt_cbc, py::arg("msg"), py::arg("key"), py::arg("IV"));
}
