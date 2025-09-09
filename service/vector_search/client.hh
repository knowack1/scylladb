#pragma once

#include "endpoint.hh"
#include <vector>
#include <seastar/core/future.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/abort_source.hh>
#include <seastar/http/client.hh>

namespace service::vector_search {

class client {
public:
    using ann_result = std::vector<seastar::temporary_buffer<char>>;

    explicit client(endpoint endpoint_);

    seastar::future<ann_result> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as);

private:
    endpoint _endpoint;
    seastar::http::experimental::client _http_client;
};


} // namespace service::vector_search
