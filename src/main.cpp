#include <iostream>
#include <openssl/evp.h>

int main() {
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "AES-256-CBC", "provider=default");
    EVP_CIPHER_free(cipher);

    std::cout << "Hello world!" << std::endl;
}
