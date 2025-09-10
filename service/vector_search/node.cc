#include "node.hh"
#include "service/vector_search/client.hh"
#include <seastar/coroutine/as_future.hh>
#include <seastar/core/sleep.hh>

namespace service::vector_search {
namespace {
auto constexpr NODE_CHECK_INTERVAL = std::chrono::seconds(10);
}

node::node(seastar::lw_shared_ptr<client> client_)
    : _client(std::move(client_)) {
}

bool node::is_up() const {
    return _is_up;
}

seastar::future<node::ann_result> node::ann(
        seastar::sstring keyspace, seastar::sstring name, std::vector<float> embedding, std::size_t limit, seastar::abort_source* as) {
    auto f = co_await seastar::coroutine::as_future(_client->ann(std::move(keyspace), std::move(name), std::move(embedding), limit, as));
    if (f.failed()) {
        _is_up = false;
        co_await seastar::coroutine::return_exception_ptr(f.get_exception());
    }
    co_return f.get();
}

void node::start() {
    (void)seastar::with_gate(_tasks_gate, [this] {
        return seastar::repeat([this] -> seastar::future<seastar::stop_iteration> {
            co_await seastar::sleep(NODE_CHECK_INTERVAL);
            co_await handle_tick();
            co_return seastar::stop_iteration::no;
        });
    });
}

seastar::future<> node::handle_tick() {
    if (_is_up) {
        auto status = co_await _client->get_status();
        _is_up = (status == client::status::serving);
    }
}


} // namespace service::vector_search
