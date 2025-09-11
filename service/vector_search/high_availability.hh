#pragma once

#include "node_group.hh"
#include "seastar/core/future.hh"
// #include "utils/observable.hh"
// #include "utils/config_file.hh"
#include <seastar/core/sstring.hh>
#include <vector>
#include <cstdint>

namespace service::vector_search {

class high_availability {
public:
    struct uri {
        seastar::sstring host;
        std::uint16_t port;
    };

    explicit high_availability(node_group::dns_resolver resolver)
        : _resolver(std::move(resolver)) {};

    high_availability(const high_availability&) = delete;
    high_availability& operator=(const high_availability&) = delete;
    high_availability(high_availability&&) = delete;
    high_availability& operator=(high_availability&&) = delete;


    seastar::future<client::ann_result> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as);

    seastar::future<> uris(std::vector<uri> uris);

private:
    using nodes = std::vector<seastar::lw_shared_ptr<node>>;

    nodes available_nodes() const;
    seastar::future<nodes> discover_nodes_in_all_groups();


    std::vector<seastar::lw_shared_ptr<node_group>> _groups;
    node_group::dns_resolver _resolver;
};


} // namespace service::vector_search
