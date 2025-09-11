#include "high_availability.hh"
#include "exception.hh"
#include <boost/algorithm/string.hpp>
#include <exception>
#include <seastar/core/when_all.hh>
#include <seastar/core/loop.hh>

using namespace seastar;

namespace service::vector_search {
namespace {

constexpr auto HTTP_REQUEST_RETRIES = 3;

// std::vector<std::string> split(std::string_view str) {
//     std::vector<std::string> result;
//     boost::split(result, str, boost::is_any_of(","));
//     return result;
// }

} // namespace

// high_availability::high_availability()
//     : _uri_observer(cfg.observe([](std::string_view uri) {

//     })) {
//     // auto uris split(cfg());
// }

seastar::future<client::ann_result> high_availability::ann(
        seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as) {
    auto nodes = available_nodes();
    // if (nodes.empty()) {
    //     nodes = co_await discover_nodes_in_all_groups();
    // }
    for (size_t i = 0; i < HTTP_REQUEST_RETRIES; i++) {
        for (const auto& node : nodes) {
            try {
                co_return co_await node->ann(std::move(keyspace), std::move(name), std::move(embedding), limit, as);
            } catch (const std::exception& e) {
                // TODO: break if aborted
                continue;
            }
        }
        nodes = co_await discover_nodes_in_all_groups();
    }
    throw service_unavailable_error();
}

seastar::future<> high_availability::uris(std::vector<uri> uris) {
    _groups.clear();
    for (const auto& u : uris) {
        _groups.push_back(seastar::make_lw_shared<node_group>(u.host, u.port, _resolver));
    }
    co_await discover_nodes_in_all_groups();
}

seastar::future<high_availability::nodes> high_availability::discover_nodes_in_all_groups() {
    co_await parallel_for_each(_groups, [](const auto& group) {
        return group->discover();
    });
    co_return available_nodes();
}

high_availability::nodes high_availability::available_nodes() const {
    nodes result;
    for (const auto& group : _groups) {
        auto tmp = group->available_nodes();
        result.insert(result.end(), tmp.begin(), tmp.end());
    }
    return result;
}


} // namespace service::vector_search
