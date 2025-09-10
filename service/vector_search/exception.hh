#pragma once

#include <seastar/http/reply.hh>
#include <stdexcept>
#include <fmt/format.h>

namespace service::vector_search {

class service_status_error : public std::runtime_error {
public:
    explicit service_status_error(seastar::http::reply::status_type status)
        : std::runtime_error(fmt::format("Vector Store error: HTTP status {}", status))
        , _status{status} {
    }


    const seastar::http::reply::status_type& status() const noexcept {
        return _status;
    }


private:
    seastar::http::reply::status_type _status;
};

class service_reply_format_error : public std::runtime_error {
public:
    explicit service_reply_format_error()
        : std::runtime_error("Vector Store returned an invalid JSON") {
    }


    const seastar::http::reply::status_type& status() const noexcept {
        return _status;
    }


private:
    seastar::http::reply::status_type _status;
};

class service_unavailable_error : public std::runtime_error {
public:
    explicit service_unavailable_error()
        : std::runtime_error("Vector Store service is unavailable") {
    }
};


} // namespace service::vector_search
