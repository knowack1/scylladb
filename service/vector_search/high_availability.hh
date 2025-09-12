#pragma once

#include "client.hh"
#include "seastar/core/future.hh"
#include <seastar/core/sstring.hh>
#include <vector>
#include <cstdint>
#include <boost/noncopyable.hpp>

namespace service::vector_search {

class high_availability : private boost::noncopyable {
public:
    struct uri {
        seastar::sstring host;
        std::uint16_t port;
    };

    using dns_resolver = std::function<seastar::future<std::optional<seastar::net::inet_address>>(seastar::sstring const&)>;

    explicit high_availability(dns_resolver resolver)
        : _resolver(std::move(resolver)) {
    }

    seastar::future<client::ann_result> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as);

    seastar::future<> set_uri(std::optional<uri> uri);

    void set_resolver(dns_resolver resolver) {
        _resolver = std::move(resolver);
    }

    seastar::future<> stop();


private:
    seastar::future<> refresh_client_address();
    seastar::future<seastar::lw_shared_ptr<client>> get_client();

    std::optional<uri> _uri;
    seastar::lw_shared_ptr<client> _client;
    dns_resolver _resolver;
};


} // namespace service::vector_search
