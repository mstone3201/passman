#pragma once

#include <string>

namespace passman::http {
    constexpr std::string_view HTTP_VERSION = "HTTP/1.1";
    constexpr std::string_view HTTP_EOL = "\r\n";
    constexpr std::string_view HTTP_DELIM = "\r\n\r\n";
    constexpr std::string_view HTTP_RESPONSE_OK = "200 OK";
    constexpr std::string_view HTTP_RESPONSE_INVALID = "401 Not Found";

    enum class request_method {
        GET,
        POST
    };

    enum class resource {
        INVALID,
        INDEX_HTML,
        INDEX_JS,
        STORE
    };

    struct request {
        request_method method = request_method::GET;
        resource resource = resource::INVALID;
    };
}
