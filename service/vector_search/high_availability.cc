#include "high_availability.hh"
#include <boost/algorithm/string.hpp>


namespace service::vector_search {
namespace {

std::vector<sstring> split(std::string_view str) {
    std::vector<sstring> result;
    boost::split(result, str, boost::is_any_of(std::string(1, ',')));
    return result;
}

} // namespace

high_availability::high_availability(utils::config_file::named_value<sstring> primary, utils::config_file::named_value<sstring> secondary)
    : _primary_observer(primary.observe([this](std::string_view uri) {
        _primary = split(uri);
    }))
    , _secondary_observer(secondary.observe([this](std::string_view uri) {
        _secondary = split(uri);
    })) {
}

high_availability::remover high_availability::on_change(listener l) {
    _listener = l;
    return [this] {
        _listener = [](std::vector<endpoint> const&) {

        };
    };
}

} // namespace service::vector_search
