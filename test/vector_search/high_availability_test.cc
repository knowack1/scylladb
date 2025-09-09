#include "service/vector_search/node.hh"
#include <seastar/testing/test_case.hh>

using namespace service::vector_search;

// SEASTAR_TEST_CASE(allows_to_register_listener) {

//     auto primary = utils::config_file::named_value<sstring>("vector_search_high_availability_primary", "http://primary1:6080,http://primary2:6080");
//     auto secondary = utils::config_file::named_value<sstring>("vector_search_high_availability_secondary", "http://secondary1:6080,http://secondary2:6080");

//     auto ha = high_availability{primary, secondary};

//     auto remover = ha.on_change([](std::vector<endpoint> const& endpoints) {
//         // BOOST_CHECK_EQUAL(endpoints.size(), 2);
//         // BOOST_CHECK_EQUAL(endpoints[0].to_string(), "http://primary1:6080");
//         // BOOST_CHECK_EQUAL(endpoints[1].to_string(), "http://primary2:6080");
//     });

//     return make_ready_future();
// }
