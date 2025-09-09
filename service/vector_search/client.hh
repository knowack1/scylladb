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
    enum class status { initializing, connecting_to_db, bootstrapping, serving };

    explicit client(endpoint endpoint_);

    // "enum": [
    //       "INITIALIZING",
    //       "CONNECTING_TO_DB",
    //       "BOOTSTRAPPING",
    //       "SERVING"
    //     ],

    seastar::future<status> get_status();

    seastar::future<ann_result> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as);

private:
    seastar::future<std::vector<seastar::temporary_buffer<char>>> request(seastar::http::request req);

    endpoint _endpoint;
    seastar::http::experimental::client _http_client;
};


} // namespace service::vector_search
