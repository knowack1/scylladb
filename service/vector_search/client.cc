#include "client.hh"
#include "exception.hh"
#include <seastar/core/format.hh>
#include <seastar/http/request.hh>
#include <seastar/http/common.hh>
#include <seastar/http/short_streams.hh>
#include <seastar/net/socket_defs.hh>
#include "utils/rjson.hh"

using namespace seastar;

namespace service::vector_search {
namespace {

auto write_ann_json(std::vector<float> embedding, std::size_t limit) -> seastar::sstring {
    return seastar::format(R"({{"embedding":[{}],"limit":{}}})", fmt::join(embedding, ","), limit);
}

auto read_status_body(std::vector<temporary_buffer<char>> body) -> client::node_status {
    auto doc = rjson::parse(std::move(body));
    if (!doc.HasMember("status")) {
        throw service_reply_format_error{};
    }

    const auto& status = doc["status"];

    if (!status.IsString()) {
        throw service_reply_format_error{};
    }

    auto status_str = std::string_view(status.GetString(), status.GetStringLength());
    if (status_str == "INITIALIZING") {
        return client::node_status::initializing;
    }
    if (status_str == "CONNECTING_TO_DB") {
        return client::node_status::connecting_to_db;
    }
    if (status_str == "BOOTSTRAPPING") {
        return client::node_status::bootstrapping;
    }
    if (status_str == "SERVING") {
        return client::node_status::serving;
    }
    throw service_reply_format_error{};
}


} // namespace

client::client(::service::vector_search::endpoint endpoint_)
    : _endpoint(std::move(endpoint_))
    , _http_client(seastar::socket_address(_endpoint.ip, _endpoint.port)) {
}

seastar::future<client::node_status> client::status() {
    auto req = http::request::make(httpd::operation_type::GET, _endpoint.host, "/api/v1/status");
    auto body = co_await request(std::move(req));
    co_return read_status_body(std::move(body));
}

seastar::future<client::ann_result> client::ann(
        seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as) {
    auto path = format("/api/v1/indexes/{}/{}/ann", keyspace, name);
    auto content = write_ann_json(std::move(embedding), limit);
    auto req = http::request::make(httpd::operation_type::POST, _endpoint.host, std::move(path));
    req.write_body("json", std::move(content));

    co_return co_await request(std::move(req));
}

seastar::future<std::vector<seastar::temporary_buffer<char>>> client::request(http::request req) {
    auto resp = std::vector<seastar::temporary_buffer<char>>{};
    auto status = seastar::http::reply::status_type::ok;
    auto handler = [&resp, &status](http::reply const& reply, input_stream<char> body) -> future<> {
        status = reply._status;
        resp = co_await util::read_entire_stream(body);
    };

    co_await _http_client.make_request(std::move(req), std::move(handler), std::nullopt, nullptr);
    if (status != seastar::http::reply::status_type::ok) {
        throw service_status_error(status);
    }
    co_return resp;
}

} // namespace service::vector_search
