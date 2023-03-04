#include "aes.h"
#include <pybind11/pybind11.h>
#include <string>

namespace py = pybind11;

/**
 * @param msg A 128-bit (16-byte) plaintext block to encrypt
 * @param key A 256-bit (32-byte) symmetric key
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
    std::array<BYTE, 16> msg_a;
    std::array<BYTE, 32> key_a;
    std::copy_n(msg_s.begin(), 16, msg_a.begin());
    std::copy_n(key_s.begin(), 32, key_a.begin());
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
    std::string msg_s = msg;
    std::string key_s = key;
    if (msg_s.size() != 16)
        throw std::length_error("Ciphertext has invalid length (should be 128 bits/16 bytes).");
    if (key_s.size() != 32)
        throw std::length_error("Key has invalid length (should be 256 bits/32 bytes).");
    std::array<BYTE, 16> msg_a;
    std::array<BYTE, 32> key_a;
    std::copy_n(msg_s.begin(), 16, msg_a.begin());
    std::copy_n(key_s.begin(), 32, key_a.begin());
    std::array<BYTE, 16> ptxt = decrypt_block(msg_a, key_a);
    return py::bytes((const char*)ptxt.data(), 16);
}

PYBIND11_MODULE(_cpplib, m) {
    m.doc() = "c++ extension library";
    m.def("encrypt_block", &py_encrypt_block, py::arg("msg"), py::arg("key"));
    m.def("decrypt_block", &py_decrypt_block, py::arg("msg"), py::arg("key"));
}
