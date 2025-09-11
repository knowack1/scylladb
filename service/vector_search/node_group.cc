#include "node_group.hh"
#include <seastar/core/sleep.hh>
#include <seastar/coroutine/as_future.hh>
#include <unordered_set>

namespace service::vector_search {
namespace {

// auto constexpr DNS_CHECK_INTERVAL = std::chrono::seconds(10);

// bool has_down(const std::vector<seastar::lw_shared_ptr<node>>& nodes) {
//     for (const auto& node : nodes) {
//         if (!node->is_up()) {
//             return true;
//         }
//     }
//     return false;
// }

} // namespace


node_group::node_group(seastar::sstring host, unsigned port, dns_resolver resolver_)
    : _host(std::move(host))
    , _port(port)
    , _resolver(std::move(resolver_)) {
}

// void node_group::start() {
//     (void)seastar::with_gate(_tasks_gate, [this] {
//         return seastar::repeat([this] -> seastar::future<seastar::stop_iteration> {
//             co_await handle_tick();
//             co_await seastar::sleep(DNS_CHECK_INTERVAL);
//             co_return seastar::stop_iteration::no;
//         });
//     });
// }

// seastar::future<> node_group::handle_tick() {
//     if (_nodes.empty() || has_down(_nodes)) {
//         auto addrs = co_await _resolver(_host);
//         handle_new_addresses(addrs);
//     }
// }

void node_group::handle_new_addresses(const std::unordered_set<seastar::net::inet_address>& addrs) {
    remove_no_longer_existing_nodes(addrs);
    add_new_nodes(addrs);
}

void node_group::remove_no_longer_existing_nodes(const std::unordered_set<seastar::net::inet_address>& addrs) {
    std::erase_if(_nodes, [&addrs](const seastar::lw_shared_ptr<node>& n) {
        return !addrs.contains(n->endpoint().ip);
    });
}

void node_group::add_new_nodes(const std::unordered_set<seastar::net::inet_address>& addrs) {

    std::unordered_set<seastar::net::inet_address> existing_addrs;
    for (const auto& node : _nodes) {
        existing_addrs.insert(node->endpoint().ip);
    }

    for (const auto& addr : addrs) {
        if (!existing_addrs.contains(addr)) {

            auto client = seastar::make_lw_shared<vector_search::client>(endpoint{_host, _port, addr});
            _nodes.emplace_back(seastar::make_lw_shared<node>(std::move(client)));
            _nodes.back()->start();
        }
    }
}

seastar::future<> node_group::discover() {
    handle_new_addresses(co_await _resolver(_host));
}

std::vector<seastar::lw_shared_ptr<node>> node_group::available_nodes() const {
    std::vector<seastar::lw_shared_ptr<node>> up_nodes;
    for (const auto& n : _nodes) {
        if (n->is_up()) {
            up_nodes.push_back(n);
        }
    }
    return up_nodes;
}

} // namespace service::vector_search
