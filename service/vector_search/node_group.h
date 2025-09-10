#pragma once

#include "node.hh"
#include "seastar/core/sstring.hh"
#include <seastar/net/inet_address.hh>
#include <seastar/core/shared_ptr.hh>
#include <vector>
#include <functional>
#include <unordered_set>
#include <seastar/core/gate.hh>

namespace service::vector_search {

// Nodes under the same hostname. DNS can return multiple IPs for a hostname.
// node_group manages a group of nodes under the same hostname.
class node_group {
public:
    using ann_result = client::ann_result;
    using dns_resolver = std::function<seastar::future<std::unordered_set<seastar::net::inet_address>>(seastar::sstring const&)>;

    explicit node_group(seastar::sstring host, unsigned port, dns_resolver resolver_);

    node_group(const node_group&) = delete;
    node_group& operator=(const node_group&) = delete;
    node_group(node_group&&) = delete;
    node_group& operator=(node_group&&) = delete;

    seastar::future<ann_result> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as);

    void start();

    seastar::future<> discover();

    std::vector<seastar::lw_shared_ptr<node>> available_nodes() const;

private:
    seastar::future<> handle_tick();
    void handle_new_addresses(const std::unordered_set<seastar::net::inet_address>& addrs);
    void remove_no_longer_existing_nodes(const std::unordered_set<seastar::net::inet_address>& addrs);
    void add_new_nodes(const std::unordered_set<seastar::net::inet_address>& addrs);

    seastar::sstring _host;
    unsigned _port;
    dns_resolver _resolver;
    seastar::gate _tasks_gate;
    std::vector<seastar::lw_shared_ptr<node>> _nodes;
};


} // namespace service::vector_search
