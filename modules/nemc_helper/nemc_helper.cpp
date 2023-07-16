#include "nemc_helper.h"
#define CPPHTTPLIB_OPENSSL_SUPPORT

static bool mdl_nemc_helper_under_destruction=false;

extern "C" void _doInit_setClientsKeepAlive() {
}

extern "C" void mdl_nemc_helper_interrupt() {
	mdl_nemc_helper_under_destruction=true;
}

NEMCUserAuthInfo::NEMCUserAuthInfo(bsoncxx::document::element const& authInfo) {
	bsoncxx::array::view bdarr=(bsoncxx::array::view)authInfo.get_array();
	some_secret=std::string(bdarr[0].get_string());
}

NEMCUserAuthInfo::operator bsoncxx::array::view() {
	stored_arr_value=bsoncxx::builder::stream::array{}<<some_secret<<bsoncxx::builder::stream::finalize;
	return stored_arr_value.view();
}

std::variant<std::string, NEMCError> NEMCUserAuthInfo::getJitsuMeiAddress() const {
	return NEMCError{"Failed to get realname address as this function is stubbed.", -1};
}

std::variant<NEMCUserAuthInfo, NEMCError> NEMCUserAuthInfo::createGuest(NEMCUserAuthInfo const& device) {
	return NEMCError{"Stubbed", -1};
}

std::variant<NEMCUserAuthInfo, NEMCError> NEMCUserAuthInfo::createGuest() {
	return NEMCError{"Stubbed", -1};
}

std::variant<NEMCUser, NEMCError> NEMCUserAuthInfo::auth() const {
	return NEMCError{"Stubbed", -1};
}

NEMCUser::NEMCUser(bsoncxx::document::element const& userInfo) {
	bsoncxx::array::view bdarr=(bsoncxx::array::view)userInfo.get_array();
	some_secret=std::string(bdarr[0].get_string());
}

NEMCUser::operator bsoncxx::array::view() {
	stored_arr_value=bsoncxx::builder::stream::array{}<<some_secret<<bsoncxx::builder::stream::finalize;
	return stored_arr_value.view();
}

bool NEMCUser::isLoggedIn() const {
	return false;
}

std::variant<std::string, NEMCError> NEMCUser::getUsername() const {
	return NEMCError{"Stubbed"};
}

std::optional<NEMCError> NEMCUser::setUsername(std::string const& username) const {
	return std::optional<NEMCError>();
}

std::variant<std::pair<std::string, std::string>, NEMCError> NEMCUser::doImpact(std::string const& serverCode, std::string const& serverPasscode, std::string const& clientKey, std::string const& username) const {
	return NEMCError{"Error authenticating to server",-1};
}

bool NEMCUser::operator==(NEMCUser const& value) const {
	return some_secret==value.some_secret;
}

bool NEMCUserAuthInfo::operator==(NEMCUserAuthInfo const& value) const {
	return some_secret==value.some_secret;
}

std::string NEMCCalculateStartType(std::string const& content, std::string const& uid) {
	return "stubbed tho";
}

std::string get_check_num(std::string const& v) {
	return "stubbed";
}