#pragma once

#include "endpoint.hh"

#include "utils/config_file.hh"
#include <vector>
#include <functional>

namespace service::vector_search {

class high_availability {
public:
    using listener = std::function<void(std::vector<endpoint> const&)>;
    using remover = std::function<void()>;

    remover on_change(listener l);

    high_availability(utils::config_file::named_value<sstring> primary, utils::config_file::named_value<sstring> secondary);

private:
    utils::observer<sstring> _primary_observer;
    utils::observer<sstring> _secondary_observer;

    std::vector<sstring> _primary;
    std::vector<sstring> _secondary;

    listener _listener = [](std::vector<endpoint> const& endpoints) {};
};


} // namespace service::vector_search
