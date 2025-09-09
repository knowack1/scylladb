#pragma once

#include <seastar/http/reply.hh>
#include <stdexcept>
#include <fmt/format.h>

namespace service::vector_search {

class vector_store_service_exception : public std::runtime_error {
public:
    explicit vector_store_service_exception(seastar::http::reply::status_type status)
        : std::runtime_error(fmt::format("Vector Store error: HTTP status {}", status))
        , _status{status} {
    }


    const seastar::http::reply::status_type& status() const noexcept {
        return _status;
    }


private:
    seastar::http::reply::status_type _status;
};

} // namespace service::vector_search
