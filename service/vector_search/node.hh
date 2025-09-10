#pragma once

#include "client.hh"
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/gate.hh>

namespace service::vector_search {

class node {
public:
    using ann_result = client::ann_result;

    explicit node(seastar::lw_shared_ptr<client> client_);

    node(const node&) = delete;
    node& operator=(const node&) = delete;
    node(node&&) = delete;
    node& operator=(node&&) = delete;

    bool is_up() const;

    const endpoint& endpoint() const {
        return _client->endpoint();
    }

    seastar::future<ann_result> ann(
            seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as);

    void start();

private:
    seastar::future<> handle_tick();

    seastar::lw_shared_ptr<client> _client;
    bool _is_up{true};
    seastar::gate _tasks_gate;
};


} // namespace service::vector_search
