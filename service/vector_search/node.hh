#pragma once

#include "endpoint.hh"
#include "err.h"

// #include "utils/config_file.hh"
// #include <seastar/net/inet_address.hh>
#include <vector>
#include <seastar/core/future.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/abort_source.hh>
#include <expected>
#include <variant>
// #include <seastar/util/functional.hh>

namespace service::vector_search {

class client {
public:
    // using listener = std::function<void(std::vector<endpoint> const&)>;
    // using remover = std::function<void()>;
    // using resolver = std::function<seastar::future<std::optional<seastar::net::inet_address>>(seastar::sstring const&)>;


    // remover on_change(listener l);

    using ann_error = std::variant<err::aborted, err::service_unavailable, err::service_error, err::service_reply_format_error>;
    using primary_keys = std::unordered_map<seastar::sstring, float>; // pk -> distance
    // struct response {
    //     http::reply::status_type status;             ///< The HTTP status of the response.
    //     std::vector<temporary_buffer<char>> content; ///< The content of the response.
    // };
    // struct  {
    //     struct 
    //     std::vector<primary_key> keys;
    //     std::vector<float> distances;
    // };

    explicit client(endpoint endpoint_);

    seastar::future<std::expected<seastar::sstring, ann_error>> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source& as);

private:
    // utils::observer<sstring> _primary_observer;

    // std::vector<sstring> _primary;
    // listener _listener = [](std::vector<endpoint> const& endpoints) {};
    // resolver _resolver;
    endpoint _endpoint;
};


} // namespace service::vector_search
