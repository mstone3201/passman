#include "crypto.hpp"

#define OPENSSL_NO_DEPRECATED

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace {
    // Files
    
    enum class bio_file_mode {
        READ,
        WRITE
    };

    std::string get_bio_file_mode_str(bio_file_mode file_mode) {
        switch(file_mode) {
        case bio_file_mode::READ:
            return "rb";
        case bio_file_mode::WRITE:
            return "wb";
        }

        throw std::exception("Unknown file mode");
    }

    class bio_file {
    public:
        explicit bio_file(const std::string& filename, bio_file_mode file_mode
        ) :
            bio(BIO_new_file(filename.c_str(),
                    get_bio_file_mode_str(file_mode).c_str()))
        {
            if(!bio)
                throw std::exception("Failed to open file");
        }
        bio_file(const bio_file&) = delete;

        ~bio_file() {
            BIO_vfree(bio);
        }

        bio_file& operator=(const bio_file&) = delete;

        const BIO* native_handle() const {
            return bio;
        }

        BIO* native_handle() {
            return bio;
        }

    private:
        BIO* const bio;
    };

    // Hashes

    enum class hash_algorithm {
        SHA256
    };

    std::string get_hash_algorithm_str(hash_algorithm algorithm) {
        switch(algorithm) {
        case hash_algorithm::SHA256:
            return "SHA256";
        }

        throw std::exception("Unknown hash algorithm");
    }

    class hash {
    public:
        explicit hash(hash_algorithm algorithm) :
            evp_md(EVP_MD_fetch(nullptr,
                    get_hash_algorithm_str(algorithm).c_str(), nullptr)
        ) {
            if(!evp_md)
                throw std::exception("Failed to create hash");
        }
        hash(const hash&) = delete;

        ~hash() {
            EVP_MD_free(evp_md);
        }

        hash& operator=(const hash&) = delete;

        const EVP_MD* native_handle() const {
            return evp_md;
        }

    private:
        EVP_MD* const evp_md = nullptr;
    };

    const hash hash_sha256(hash_algorithm::SHA256);

    // Ciphers

    enum class cipher_algorithm {
        DES_EDE3_CBC
    };

    std::string get_cipher_algorithm_str(cipher_algorithm algorithm) {
        switch(algorithm) {
        case cipher_algorithm::DES_EDE3_CBC:
            return "DES-EDE3-CBC";
        }

        throw std::exception("Unknown cipher algorithm");
    }

    class cipher {
    public:
        explicit cipher(cipher_algorithm algorithm) :
            evp_cipher(EVP_CIPHER_fetch(nullptr,
                    get_cipher_algorithm_str(algorithm).c_str(), nullptr)
        ) {
            if(!evp_cipher)
                throw std::exception("Failed to create cipher");
        }
        cipher(const cipher&) = delete;

        ~cipher() {
            EVP_CIPHER_free(evp_cipher);
        }

        cipher& operator=(const cipher&) = delete;

        const EVP_CIPHER* native_handle() const {
            return evp_cipher;
        }

    private:
        EVP_CIPHER* const evp_cipher = nullptr;
    };

    const cipher cipher_des_ede3_cbc(cipher_algorithm::DES_EDE3_CBC);

    // Keys

    enum class key_size {
        FAST_2048,
        BALANCED_4096,
        SECURE_8192
    };

    size_t get_rsa_key_size(key_size size) {
        switch(size) {
        case key_size::FAST_2048:
            return 2048;
        case key_size::BALANCED_4096:
            return 4096;
        case key_size::SECURE_8192:
            return 8192;
        }

        throw std::exception("Unknown key size");
    }

    class rsa_keypair {
    public:
        explicit rsa_keypair(key_size size) :
            evp_pkey(EVP_RSA_gen(get_rsa_key_size(size))
        ) {
            if(!evp_pkey)
                throw std::exception("Failed to create rsa keypair");
        }
        rsa_keypair(const rsa_keypair&) = delete;

        ~rsa_keypair() {
            EVP_PKEY_free(evp_pkey);
        }

        rsa_keypair& operator=(const rsa_keypair&) = delete;

        void write_private_key(const std::string& filename,
            std::string_view password) const
        {
            bio_file bio(filename, bio_file_mode::WRITE);

            if(!PEM_write_bio_PrivateKey(bio.native_handle(), evp_pkey,
                cipher_des_ede3_cbc.native_handle(),
                reinterpret_cast<const unsigned char*>(password.data()),
                password.size(), nullptr, nullptr))
            {
                throw std::exception("Failed to write private key");
            }
        }

        const EVP_PKEY* native_handle() const {
            return evp_pkey;
        }

        EVP_PKEY* native_handle() {
            return evp_pkey;
        }

    private:
        EVP_PKEY* const evp_pkey;
    };

    std::string get_dh_group_str(key_size size) {
        switch(size) {
        case key_size::FAST_2048:
            return "ffdhe2048";
        case key_size::BALANCED_4096:
            return "ffdhe4096";
        case key_size::SECURE_8192:
            return "ffdhe8192";
        }

        throw std::exception("Unknown key size");
    }

    class dh_keypair {
    public:
        explicit dh_keypair(key_size size) {
            EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "DH",
                nullptr);
            if(!context)
                throw std::exception("Failed to create DH keypair context");

            // Set key generation parameters
            std::string group = get_dh_group_str(size);
            OSSL_PARAM parameters[]{
                OSSL_PARAM_construct_utf8_string("group", group.data(),
                    group.size()),
                OSSL_PARAM_construct_end()
            };

            // Generate key
            if(EVP_PKEY_keygen_init(context) != 1) {
                EVP_PKEY_CTX_free(context);
                throw std::exception("Failed to initialize DH keypair\
                    generation");
            }
            if(!EVP_PKEY_CTX_set_params(context, parameters)) {
                EVP_PKEY_CTX_free(context);
                throw std::exception("Failed to set DH keypair parameters");
            }
            if(EVP_PKEY_generate(context, &evp_pkey) != 1 || !evp_pkey) {
                EVP_PKEY_CTX_free(context);
                throw std::exception("Failed to create DH keypair");
            }

            EVP_PKEY_CTX_free(context);
        }
        dh_keypair(const dh_keypair&) = delete;

        ~dh_keypair() {
            EVP_PKEY_free(evp_pkey);
        }

        dh_keypair& operator=(const dh_keypair&) = delete;

        void write(const std::string& filename) const
        {
            bio_file bio(filename, bio_file_mode::WRITE);

            if(!PEM_write_bio_PrivateKey(bio.native_handle(), evp_pkey, nullptr,
                nullptr, 0, nullptr, nullptr))
            {
                throw std::exception("Failed to write DH key");
            }
        }

        const EVP_PKEY* native_handle() const {
            return evp_pkey;
        }

    private:
        EVP_PKEY* evp_pkey = nullptr;
    };

    // Certificates

    class x509_certificate {
    public:
        explicit x509_certificate(const std::string& hostname,
            rsa_keypair& keypair) : x509(X509_new())
        {
            if(!x509)
                throw std::exception("Failed to create x509 certificate");

            // X509_getm_notBefore will not fail
            if(!X509_gmtime_adj(X509_getm_notBefore(x509), 0))
                throw std::exception("Failed to set x509 certificate not before\
                    time");
            // X509_getm_notAfter will not fail
            if(!X509_gmtime_adj(X509_getm_notAfter(x509), 315360000))
                throw std::exception("Failed to set x509 certificate not after\
                    time");

            if(!X509_set_pubkey(x509, keypair.native_handle()))
                throw std::exception("Failed to set x509 certificate public\
                    key");

            // X509_get_subject_name will not fail
            X509_NAME* name = X509_get_subject_name(x509);
            if(!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("passman"), -1, -1, 0))
            {
                throw std::exception("Failed to set x509 organization");
            }
            if(!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(hostname.c_str()), -1,
                -1, 0))
            {
                throw std::exception("Failed to set x509 certificate common\
                    name");
            }

            if(!X509_set_issuer_name(x509, name))
                throw std::exception("Failed to set x509 certificate issuer\
                    name");

            if(!X509_sign(x509, keypair.native_handle(),
                hash_sha256.native_handle()))
            {
                throw std::exception("Failed to sign x509 certificate");
            }
        }
        x509_certificate(const x509_certificate&) = delete;

        ~x509_certificate() {
            X509_free(x509);
        }

        x509_certificate& operator=(const x509_certificate&) = delete;

        void write(const std::string& filename) const {
            bio_file bio(filename, bio_file_mode::WRITE);

            if(!PEM_write_bio_X509(bio.native_handle(), x509))
                throw std::exception("Failed to write certificate");
        }

        const X509* native_handle() const {
            return x509;
        }

    private:
        X509* const x509;
    };
}

namespace passman::crypto {
    const std::string PRIVATE_KEY_FILENAME = "private_key.pem";
    const std::string CERTIFICATE_FILENAME = "certificate.pem";
    const std::string DH_FILENAME = "dh.pem";

    void generate_certificate(const std::string& hostname,
        std::string_view password)
    {
        rsa_keypair keypair(key_size::SECURE_8192);
        x509_certificate certificate(hostname, keypair);

        keypair.write_private_key(PRIVATE_KEY_FILENAME, password);
        certificate.write(CERTIFICATE_FILENAME);
    }

    void generate_dh_parameters() {
        dh_keypair keypair(key_size::SECURE_8192);
        keypair.write(DH_FILENAME);
    }
}
