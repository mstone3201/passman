#pragma once

#include <string>
#include <string_view>

namespace passman::crypto {
    extern const std::string PRIVATE_KEY_FILENAME;
    extern const std::string CERTIFICATE_FILENAME;
    extern const std::string DH_FILENAME;

    void generate_certificate(const std::string& hostname,
        std::string_view password);
    void generate_dh_parameters();
}
