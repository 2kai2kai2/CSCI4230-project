#include "aes.h"
#include <pybind11/operators.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>

namespace py = pybind11;

/**
 * @param msg A 128-bit (16-byte) plaintext block to encrypt
 * @param key
 * @return py::bytes The cooresponding 128-bit (16-byte) ciphertext
 * @throws std::length_error if inputs are invalid
 */
py::bytes py_encrypt_block(py::bytes msg, py::bytes key) {
    std::string msg_s = msg;
    std::string key_s = key;
    if (msg_s.size() != 16)
        throw std::length_error("Plaintext has invalid length (should be 128 bits/16 bytes).");
    if (key_s.size() != 32)
        throw std::length_error("Key has invalid length (should be 256 bits/32 bytes).");
    std::array<std::bitset<8>, 16> msg_a;
    std::array<std::bitset<8>, 32> key_a;
    for (size_t i = 0; i < 16; ++i)
        msg_a[i] = msg_s[i];
    for (size_t i = 0; i < 32; ++i)
        key_a[i] = key_s[i];
    std::bitset<128> ctxt = encrypt_block(concat_bitset(msg_a), concat_bitset(key_a));
    std::string out;
    for (size_t i = 0; i < 16; ++i)
        out.push_back(sub_bitset<8>(ctxt, i).to_ulong());
    return py::bytes(out);
}

/**
 * @param msg A 128-bit (16-byte) ciphertext block to decrypt
 * @param key
 * @return py::bytes The cooresponding 128-bit (16-byte) plaintext
 * @throws std::length_error if inputs are invalid
 */
py::bytes py_decrypt_block(py::bytes msg, py::bytes key) {
    std::string msg_s = msg;
    std::string key_s = key;
    if (msg_s.size() != 16)
        throw std::length_error("Ciphertext has invalid length (should be 128 bits/16 bytes).");
    if (key_s.size() != 32)
        throw std::length_error("Key has invalid length (should be 256 bits/32 bytes).");
    std::array<std::bitset<8>, 16> msg_a;
    std::array<std::bitset<8>, 32> key_a;
    for (size_t i = 0; i < 16; ++i)
        msg_a[i] = msg_s[i];
    for (size_t i = 0; i < 32; ++i)
        key_a[i] = key_s[i];
    std::bitset<128> ptxt = decrypt_block(concat_bitset(msg_a), concat_bitset(key_a));
    std::string out;
    for (size_t i = 0; i < 16; ++i)
        out.push_back(sub_bitset<8>(ptxt, i).to_ulong());
    return py::bytes(out);
}

PYBIND11_MODULE(_cpplib, m) {
    m.doc() = "c++ extension library";
    m.def("encrypt_block", &py_encrypt_block, py::arg("msg"), py::arg("key"));
    m.def("decrypt_block", &py_decrypt_block, py::arg("msg"), py::arg("key"));
}
