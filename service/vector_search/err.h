#pragma once

#include <seastar/http/reply.hh>


namespace service::vector_search {

struct err {
    struct aborted {};
    struct addr_unavailable {};
    struct service_unavailable {};
    struct disabled {};
    struct service_error {
        seastar::http::reply::status_type status; ///< The HTTP status code from the vector-store service.
    };
    struct service_reply_format_error {};
};


} // namespace service::vector_search
