#pragma once

#include <unordered_map>
#include <coroutine>
#include <array>
#include <algorithm>

#include "http.hpp"

namespace passman::http {
    namespace {
        // request_method and string mapping
        constexpr std::array<std::pair<request_method, std::string_view>, 2>
            request_methods({{request_method::GET, "GET"},
                {request_method::POST, "POST"}});

        // Maximum length of request method string
        constexpr std::string::size_type rm_max_size = std::max_element(
            request_methods.cbegin(), request_methods.cend(),
            [](const std::pair<request_method, std::string_view>& a,
                const std::pair<request_method, std::string_view>& b)
            {
                return a.second.size() < b.second.size();
            }
        )->second.size();

        // URI and resource mapping
        const std::unordered_map<std::string, resource> uri_mapping{
            {"/", resource::INDEX_HTML},
            {"/index.html", resource::INDEX_HTML},
            {"/index.js", resource::INDEX_JS},
            {"/store", resource::STORE}
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

    inline parser_coroutine parse_request(
        std::string_view& buffer_view,
        request& http_request
    ) {
        using return_type =
            passman::http::parser_coroutine::promise_type::return_type;

        // Parse request method

        // Request method string
        std::string rm_str;
        rm_str.reserve(rm_max_size);

        // Search for first space
        while(true) {
            for(const char c : buffer_view) {
                if(c == ' ')
                    goto method_found;
                else if(rm_str.size() == rm_max_size)
                    co_return return_type::INVALID;
                
                rm_str.push_back(c);
                buffer_view.remove_prefix(1);
            }

            co_await std::suspend_always();
        }
    method_found:

        // Identify request method
        for(const auto& method : request_methods) {
            if(method.second == rm_str) {
                http_request.method = method.first;
                goto method_valid;
            }
        }
        co_return return_type::INVALID;
    method_valid:

        // Parse uri

        constexpr std::string::size_type uri_max_size = 1024;

        // Consume previous space
        buffer_view.remove_prefix(1);
        
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

        const auto resource_it = uri_mapping.find(uri);
        http_request.resource = resource_it == uri_mapping.cend() ?
            resource::INVALID : resource_it->second;

        // Parse header
        // As of now we ignore whatever is in the header

        constexpr std::string::size_type header_max_size = 8192;
        
        // method + ' ' + uri + remainder of buffer_view
        std::string::size_type bytes_read = rm_str.size() + uri.size() + 1;

        // Read until http delimiter

        std::string_view::const_iterator delim_it = HTTP_DELIM.cbegin();

        while(true) {
            for(const char c : buffer_view) {
                if(c == *delim_it) {
                    if(++delim_it == HTTP_DELIM.cend())
                        goto delim_found;
                } else
                    delim_it = HTTP_DELIM.cbegin();
            }
        
            bytes_read += buffer_view.size();

            if(bytes_read >= header_max_size)
                co_return return_type::INVALID;

            co_await std::suspend_always();
        }
    delim_found:
        
        co_return return_type::VALID;
    }
}
