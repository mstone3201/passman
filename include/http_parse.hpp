#pragma once

#include <unordered_map>
#include <coroutine>
#include <array>
#include <algorithm>

#include "http.hpp"

// TODO: remove debug print statements
#include <iostream>

namespace passman::http {
    namespace {
        const std::unordered_map<std::string_view, request_method>
            method_mapping{
                {"GET", request_method::GET},
                {"POST", request_method::POST}
            };

        const std::string::size_type method_max_size = std::max_element(
            method_mapping.cbegin(), method_mapping.cend(),
            [](const std::pair<std::string_view, request_method>& a,
                const std::pair<std::string_view, request_method>& b)
            {
                return a.first.size() < b.first.size();
            }
        )->first.size();

        const std::unordered_map<std::string_view, resource> uri_mapping{
            {"/", resource::INDEX_HTML},
            {"/index.html", resource::INDEX_HTML},
            {"/index.js", resource::INDEX_JS},
            {"/store", resource::STORE}
        };

        enum class http_header {
            CONTENT_LENGTH,
            SERVER_TOKEN
        };

        const std::unordered_map<std::string_view, http_header> header_mapping{
            {"Content-Length", http_header::CONTENT_LENGTH},
            {"Server-Token", http_header::SERVER_TOKEN}
        };
    }

    enum class parse_result {
        VALID,
        INVALID,
        INCOMPLETE
    };

    class parser_coroutine {
    public:
        struct promise_type {
            enum class return_type {
                VALID,
                INVALID
            };

            parser_coroutine get_return_object() {
                return parser_coroutine(
                    std::coroutine_handle<promise_type>::from_promise(*this));
            }

            std::suspend_always initial_suspend() { return {}; }
            std::suspend_always final_suspend() noexcept { return {}; }

            void unhandled_exception() {}
            
            void return_value(return_type value) {
                switch(value) {
                case return_type::VALID:
                    result = parse_result::VALID;
                    break;
                case return_type::INVALID:
                    result = parse_result::INVALID;
                    break;
                }
            }

            parse_result result = parse_result::INCOMPLETE;
        };

        explicit parser_coroutine(std::coroutine_handle<promise_type> handle) :
            handle(handle) {}
        parser_coroutine(const parser_coroutine&) = delete;

        ~parser_coroutine() {
            handle.destroy();
        }

        parser_coroutine& operator=(const parser_coroutine&) = delete;

        parse_result parse() {
            if(!handle.done())
                handle();

            return handle.promise().result;
        }

    private:
        std::coroutine_handle<promise_type> handle;
    };

    /*
    POST requests must be authorized, otherwise they are rejected
    Only POST requests are permitted to have a body (although it may be empty)
    GET requests can optionally be authorized
    */
    inline parser_coroutine parse_request(
        std::string_view& buffer_view,
        request& http_request,
        std::string_view server_token
    ) {
        using return_type =
            passman::http::parser_coroutine::promise_type::return_type;

        // Parse request method

        std::string method_str;

        // Search for first space
        while(true) {
            for(const char c : buffer_view) {
                if(c == ' ')
                    goto method_found;
                else if(method_str.size() == method_max_size)
                    co_return return_type::INVALID;
                
                method_str.push_back(c);
                buffer_view.remove_prefix(1);
            }

            co_await std::suspend_always();
        }
    method_found:
        // Consume the space
        buffer_view.remove_prefix(1);

        // Identify request method
        const auto method_it = method_mapping.find(method_str);
        if(method_it != method_mapping.cend())
            http_request.method = method_it->second;
        else
            co_return return_type::INVALID;

        // Parse uri

        constexpr std::string::size_type uri_max_size = 1024;
        std::string uri;

        // Search for next space
        while(true) {
            for(const char c : buffer_view) {
                if(c == ' ')
                    goto uri_found;
                else if(uri.size() == uri_max_size)
                    co_return return_type::INVALID;
                
                uri.push_back(c);
                buffer_view.remove_prefix(1);
            }

            co_await std::suspend_always();
        }
    uri_found:
        // Consume the space
        buffer_view.remove_prefix(1);

        // Identify requested resource
        const auto resource_it = uri_mapping.find(uri);
        if(resource_it != uri_mapping.cend())
            http_request.resource = resource_it->second;
        else {
            http_request.resource = resource::INVALID;

            std::cout << "Invalid " << method_str << " request for " << uri
                << std::endl;;

            co_return return_type::INVALID;
        }

        // Read HTTP version

        // HTTP/X.Y\r
        constexpr std::string::size_type version_max_size = 9;
        std::string version_str;

        // Search for next \n
        while(true) {
            for(const char c : buffer_view) {
                if(c == '\n')
                    goto version_found;
                else if(version_str.size() == version_max_size)
                    co_return return_type::INVALID;

                version_str.push_back(c);
                buffer_view.remove_prefix(1);
            }

            co_await std::suspend_always();
        }
    version_found:
        // Consume the \n
        buffer_view.remove_prefix(1);

        // If line ended in \r\n then remove \r
        if(!version_str.empty() && version_str.back() == '\r')
            version_str.pop_back();

        // Parse header

        constexpr std::string::size_type header_max_size = 8192;
        std::string::size_type bytes_read = 0;

        std::string::size_type content_length = 0;

        // Look through the headers
        while(true) {
            std::string header_line;

            // Search for next \n
            while(true) {
                for(const char c : buffer_view) {
                    if(c == '\n')
                        goto header_line_found;
                    else if(bytes_read == header_max_size)
                        co_return return_type::INVALID;

                    header_line.push_back(c);
                    ++bytes_read;
                    buffer_view.remove_prefix(1);
                }

                co_await std::suspend_always();
            }
        header_line_found:
            // Consume the \n
            buffer_view.remove_prefix(1);

            // If line ended in \r\n then remove \r
            if(!header_line.empty() && header_line.back() == '\r')
                header_line.pop_back();

            // Found HTTP_DELIM
            if(header_line.empty())
                goto header_delim_found;

            // Split into key and value

            const auto header_split_pos = header_line.find_first_of(':');
            if(header_split_pos == std::string::npos || header_split_pos == 0)
                co_return return_type::INVALID;
            // Skip spaces
            const auto value_start_pos = header_line.find_first_not_of(' ',
                header_split_pos + 1);
            if(value_start_pos == std::string::npos)
                co_return return_type::INVALID;
                
            // Views of key and value
            const std::string_view header_key(header_line.cbegin(),
                header_line.cbegin() + header_split_pos);
            const std::string_view header_value(
                header_line.cbegin() + value_start_pos, header_line.cend());

            // Find known headers
            const auto header_it = header_mapping.find(header_key);
            if(header_it != header_mapping.cend()) {
                switch(header_it->second) {
                case http_header::CONTENT_LENGTH:
                    {
                        const char* end = header_value.data()
                            + header_value.size();
                        if(std::from_chars(header_value.data(), end,
                            content_length).ptr != end)
                        {
                            co_return return_type::INVALID;
                        }
                        break;
                    }
                case http_header::SERVER_TOKEN:
                    if(header_value == server_token)
                        http_request.authorized = true;
                    break;
                }
            }
        }
    header_delim_found:

        // Read body

        if(http_request.method == request_method::POST) {
            // Only allow POSTs from authorized requests
            if(!http_request.authorized)
                co_return return_type::INVALID;

            if(content_length) {
                std::string body;

                while(true) {
                    if(body.size() + buffer_view.size() >= content_length) {
                        body.append(buffer_view.data(), content_length - body.size());
                        goto body_read;
                    } else
                        body.append(buffer_view);

                    co_await std::suspend_always();
                }
            body_read:

                http_request.body = std::move(body);
            }
        }

        if(http_request.authorized)
            std::cout << "Authorized ";
        std::cout << method_str << " request for " << uri;
        if(http_request.body)
            std::cout << " with body (" << http_request.body->size() << ") "
                << *http_request.body;
        std::cout << std::endl;
        
        co_return return_type::VALID;
    }
}
