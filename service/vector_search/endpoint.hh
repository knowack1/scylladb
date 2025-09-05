#pragma once

#include <seastar/core/sstring.hh>
#include <seastar/net/inet_address.hh>

namespace service::vector_search {

struct endpoint {
    seastar::sstring host;
    seastar::sstring port;
    seastar::net::inet_address ip;
};

} // namespace service::vector_search
