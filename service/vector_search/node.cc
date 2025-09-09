#include "node.hh"
#include "service/vector_search/endpoint.hh"
// #include <boost/algorithm/string.hpp>
// #include "utils/rjson.hh"
#include <seastar/core/format.hh>

namespace service::vector_search {
namespace {

// auto write_ann_json(std::vector<float> embedding, std::size_t limit) -> seastar::sstring {
//     return seastar::format(R"({{"embedding":[{}],"limit":{}}})", fmt::join(embedding, ","), limit);
// }

// auto read_ann_json(rjson::value const& json) -> std::expected<node::ann_result, node::ann_error> {
//     if (!json.HasMember("primary_keys")) {
//         return std::unexpected{err::service_reply_format_error{}};
//     }
//     auto const& keys_json = json["primary_keys"];
//     if (!keys_json.IsObject()) {
//         return std::unexpected{err::service_reply_format_error{}};
//     }

//     if (!json.HasMember("distances")) {
//         return std::unexpected{err::service_reply_format_error{}};
//     }
//     auto const& distances_json = json["distances"];
//     if (!distances_json.IsArray()) {
//         return std::unexpected{err::service_reply_format_error{}};
//     }
//     auto const& distances_arr = json["distances"].GetArray();

//     auto pk_from_json(rjson::value const& item, std::size_t idx, schema_ptr const& schema) -> std::expected<partition_key, ann_error> {
//     std::vector<bytes> raw_pk;
//     for (const column_definition& cdef : schema->partition_key_columns()) {
//         auto raw_value = get_key_column_value(item, idx, cdef);
//         if (!raw_value) {
//             return std::unexpected{raw_value.error()};
//         }
//         raw_pk.emplace_back(*raw_value);
//     }
//     return partition_key::from_exploded(raw_pk);
// }


//     auto size = distances_arr.Size();
//     auto keys = primary_keys{};
//     for (auto idx = 0U; idx < size; ++idx) {
//         auto pk = pk_from_json(keys_json, idx, schema);
//         if (!pk) {
//             return std::unexpected{pk.error()};
//         }
//         auto ck = ck_from_json(keys_json, idx, schema);
//         if (!ck) {
//             return std::unexpected{ck.error()};
//         }
//         keys.push_back(primary_key{dht::decorate_key(*schema, *pk), *ck});
//     }
//     return std::move(keys);
// }


// std::vector<sstring> split(std::string_view str) {
//     std::vector<sstring> result;
//     boost::split(result, str, boost::is_any_of(std::string(1, ',')));
//     return result;
// }

} // namespace

client::client(endpoint endpoint_)
    : _endpoint(std::move(endpoint_)) {
}

// seastar::future<std::expected<node::ann_result, node::ann_error>> client::ann(
//         seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source& as) {
// }

// node::remover node::on_change(listener l) {
//     _listener = l;
//     return [this] {
//         _listener = [](std::vector<endpoint> const&) {

//         };
//     };
// }

// future<std::vector<endpoint>> high_availability::get_endpoints() {
//     _pr
// }

} // namespace service::vector_search
