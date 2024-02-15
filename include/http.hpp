#pragma once

#include <string>

namespace passman::http {
    enum class request_method {
        GET,
        POST
    };

    struct request {
        request_method method;
        std::string uri;
    };
}
