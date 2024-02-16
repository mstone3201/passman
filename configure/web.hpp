#pragma once

#include <string_view>

namespace passman {
    constexpr std::string_view HTTP_INDEX_HTML = "HTTP/1.1 200 OK\r\n\r\n\
        @WEB_INDEX_HTML@\r\n\r\n";
}
