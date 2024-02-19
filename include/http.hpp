#pragma once

#include <string>
#include <optional>
#include <unordered_map>

namespace passman::http {
    constexpr std::string_view HTTP_VERSION = "HTTP/1.1";
    constexpr std::string_view HTTP_DELIM = "\r\n\r\n";

    enum class request_method {
        GET,
        POST
    };

    struct request {
        request_method method = request_method::GET;
        std::string uri;
    };

    enum class response_status {
        OK,
        INVALID
    };

    struct response {
        response_status status = response_status::INVALID;
        std::optional<std::string_view> content;
    };

    inline std::string get_response_str(const response& response)
    {
        std::string result(HTTP_VERSION);
        result.push_back(' ');

        switch(response.status) {
        case response_status::OK:
            result.append("200 OK");
            break;
        case response_status::INVALID:
            result.append("401 Not Found");
            break;
        }

        result.append(HTTP_DELIM);

        if(response.content)
            result.append(*response.content).append(HTTP_DELIM);

        return std::move(result);
    }

    enum class resource {
        INDEX_HTML,
        INDEX_JS,
        TEST
    };

    inline const std::unordered_map<std::string, resource> uri_mapping{
        {"/", resource::INDEX_HTML},
        {"/index.html", resource::INDEX_HTML},
        {"/index.js", resource::INDEX_JS},
        {"/test", resource::TEST}
    };
}
