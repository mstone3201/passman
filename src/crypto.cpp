#include "crypto.hpp"

#define OPENSSL_NO_DEPRECATED

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

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

        throw std::exception();
    }

    class bio_file {
    public:
        explicit bio_file(const std::string& filename, bio_file_mode file_mode
        ) :
            bio(BIO_new_file(filename.c_str(),
                    get_bio_file_mode_str(file_mode).c_str()))
        {
            if(!bio)
                throw std::exception();
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
        SHA2_512
    };

    std::string get_hash_algorithm_str(hash_algorithm algorithm) {
        switch(algorithm) {
        case hash_algorithm::SHA2_512:
            return "SHA2-512";
        }

        throw std::exception();
    }

    class hash {
    public:
        explicit hash(hash_algorithm algorithm) :
            evp_md(EVP_MD_fetch(nullptr,
                    get_hash_algorithm_str(algorithm).c_str(), nullptr)
        ) {
            if(!evp_md)
                throw std::exception();
        }
        hash(const hash&) = delete;

        ~hash() {
            EVP_MD_free(evp_md);
        }

        hash& operator=(const hash&) = delete;

        std::string digest(std::string_view data) const {
            int digest_size = EVP_MD_get_size(evp_md);
            if(digest_size == -1)
                throw std::exception();

            std::string result(digest_size, '\0');

            EVP_MD_CTX* context = EVP_MD_CTX_new();
            if(!context)
                throw std::exception();

            if(!EVP_DigestInit(context, evp_md)) {
                EVP_MD_CTX_free(context);
                throw std::exception();
            }

            if(!EVP_DigestUpdate(context, data.data(), data.size())) {
                EVP_MD_CTX_free(context);
                throw std::exception();
            }

            if(!EVP_DigestFinal(context,
                reinterpret_cast<unsigned char*>(result.data()), nullptr))
            {
                EVP_MD_CTX_free(context);
                throw std::exception();
            }

            EVP_MD_CTX_free(context);

            return std::move(result);
        }

        const EVP_MD* native_handle() const {
            return evp_md;
        }

    private:
        EVP_MD* const evp_md = nullptr;
    };

    const hash hash_sha2_512(hash_algorithm::SHA2_512);

    // Ciphers

    enum class cipher_algorithm {
        DES_EDE3_CBC
    };

    std::string get_cipher_algorithm_str(cipher_algorithm algorithm) {
        switch(algorithm) {
        case cipher_algorithm::DES_EDE3_CBC:
            return "DES-EDE3-CBC";
        }

        throw std::exception();
    }

    class cipher {
    public:
        explicit cipher(cipher_algorithm algorithm) :
            evp_cipher(EVP_CIPHER_fetch(nullptr,
                    get_cipher_algorithm_str(algorithm).c_str(), nullptr)
        ) {
            if(!evp_cipher)
                throw std::exception();
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

        throw std::exception();
    }

    class rsa_keypair {
    public:
        explicit rsa_keypair(key_size size) :
            evp_pkey(EVP_RSA_gen(get_rsa_key_size(size))
        ) {
            if(!evp_pkey)
                throw std::exception();
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
                throw std::exception();
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

        throw std::exception();
    }

    class dh_keypair {
    public:
        explicit dh_keypair(key_size size) {
            EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_from_name(nullptr, "DH",
                nullptr);
            if(!context)
                throw std::exception();

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
                throw std::exception();
            }
            if(!EVP_PKEY_CTX_set_params(context, parameters)) {
                EVP_PKEY_CTX_free(context);
                throw std::exception();
            }
            if(EVP_PKEY_generate(context, &evp_pkey) != 1 || !evp_pkey) {
                EVP_PKEY_CTX_free(context);
                throw std::exception();
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
                throw std::exception();
            }
        }

        const EVP_PKEY* native_handle() const {
            return evp_pkey;
        }

    private:
        EVP_PKEY* evp_pkey = nullptr;
    };

    // Certificates

    class x509_extension {
    public:
        explicit x509_extension(X509* x509, int nid, const char* value) {
            X509V3_CTX ext_context;
            X509V3_set_ctx_nodb(&ext_context);
            X509V3_set_ctx(&ext_context, x509, x509, nullptr, nullptr, 0);

            extension = X509V3_EXT_conf_nid(nullptr, &ext_context, nid, value);
            if(!extension)
                throw std::exception();
        }
        x509_extension(const x509_extension&) = delete;

        ~x509_extension() {
            X509_EXTENSION_free(extension);
        }

        x509_extension& operator=(const x509_extension&) = delete;

        const X509_EXTENSION* native_handle() const {
            return extension;
        }

        X509_EXTENSION* native_handle() {
            return extension;
        }
    private:
        X509_EXTENSION* extension = nullptr;
    };

    class x509_certificate {
    public:
        explicit x509_certificate(const std::string& hostname,
            rsa_keypair& keypair) : x509(X509_new())
        {
            if(!x509)
                throw std::exception();

            if(!X509_set_version(x509, 2))
                throw std::exception();

            // X509_get_serialNumber will not fail
            if(!ASN1_INTEGER_set(X509_get_serialNumber(x509), 1))
                throw std::exception();

            // X509_getm_notBefore will not fail
            if(!X509_gmtime_adj(X509_getm_notBefore(x509), 0))
                throw std::exception();
            // X509_getm_notAfter will not fail
            if(!X509_gmtime_adj(X509_getm_notAfter(x509), 315360000))
                throw std::exception();

            if(!X509_set_pubkey(x509, keypair.native_handle()))
                throw std::exception();

            // X509_get_subject_name will not fail
            X509_NAME* name = X509_get_subject_name(x509);
            if(!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("passman"), -1, -1, 0))
            {
                throw std::exception();
            }
            if(!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>(hostname.c_str()), -1,
                -1, 0))
            {
                throw std::exception();
            }

            if(!X509_set_issuer_name(x509, name))
                throw std::exception();

            if(!X509_add_ext(x509,
                x509_extension(x509, NID_subject_key_identifier,
                    "hash"
                ).native_handle(), -1))
            {
                throw std::exception();
            }

            if(!X509_add_ext(x509,
                x509_extension(x509, NID_authority_key_identifier,
                    "keyid:always"
                ).native_handle(), -1))
            {
                throw std::exception();
            }

            if(!X509_add_ext(x509,
                x509_extension(x509, NID_basic_constraints,
                    "critical,CA:TRUE"
                ).native_handle(), -1))
            {
                throw std::exception();
            }

            if(!X509_add_ext(x509,
                x509_extension(x509, NID_subject_alt_name,
                    ("IP:" + hostname).c_str()
                ).native_handle(), -1))
            {
                throw std::exception();
            }

            if(!X509_sign(x509, keypair.native_handle(),
                hash_sha2_512.native_handle()))
            {
                throw std::exception();
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
                throw std::exception();
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

    std::string hash(std::string_view data) {
        return std::move(hash_sha2_512.digest(data));
    }

    std::string base64_encode(std::string_view data) {
        // Limit size of data to uint32_t max and avoid overflow
        if(data.size() >= std::numeric_limits<uint32_t>::max())
            throw std::exception();

        std::string result(data.size() / 48 * 64
            + (data.size() % 48 + 2) / 3 * 4 + 1, '\0');

        EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()),
            reinterpret_cast<const unsigned char*>(data.data()), data.size());

        // Pop off the null terminator
        result.pop_back();

        return std::move(result);
    }
}
