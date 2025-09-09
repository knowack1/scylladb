#include "client.hh"
#include "exception.hh"
#include <seastar/core/format.hh>
#include <seastar/http/request.hh>
#include <seastar/http/common.hh>
#include <seastar/http/short_streams.hh>

using namespace seastar;

namespace service::vector_search {
namespace {

auto write_ann_json(std::vector<float> embedding, std::size_t limit) -> seastar::sstring {
    return seastar::format(R"({{"embedding":[{}],"limit":{}}})", fmt::join(embedding, ","), limit);
}

} // namespace

seastar::future<client::ann_result> client::ann(
        seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as) {

    auto path = format("/api/v1/indexes/{}/{}/ann", keyspace, name);
    auto content = write_ann_json(std::move(embedding), limit);


    auto req = http::request::make(httpd::operation_type::POST, _endpoint.host, std::move(path));
    req.write_body("json", std::move(content));

    auto resp = ann_result{};
    auto status = seastar::http::reply::status_type::ok;
    auto handler = [&resp, &status](http::reply const& reply, input_stream<char> body) -> future<> {
        status = reply._status;
        resp = co_await util::read_entire_stream(body);
    };

    co_await _http_client.make_request(std::move(req), std::move(handler), std::nullopt, as);
    if (status != seastar::http::reply::status_type::ok) {
        throw vector_store_service_exception(status);
    }
    co_return resp;
}

} // namespace service::vector_search
