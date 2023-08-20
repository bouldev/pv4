#include "nemc_helper.h"

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

std::string NEMCUserAuthInfo::getJitsuMeiAddress() const {
	throw NEMCError{"Failed to get realname address as this function is stubbed.", -1};
}

NEMCUserAuthInfo NEMCUserAuthInfo::loginWithEmail(std::string const& e,std::string const& p,std::string const& r) {
	throw NEMCError{"Stubbed", -1};
}

NEMCUserAuthInfo NEMCUserAuthInfo::createGuest(NEMCUserAuthInfo const& device) {
	throw NEMCError{"Stubbed", -1};
}

NEMCUserAuthInfo NEMCUserAuthInfo::createGuest(std::string const& rid) {
	throw NEMCError{"Stubbed", -1};
}

NEMCUser NEMCUserAuthInfo::auth() const {
	throw NEMCError{"Stubbed", -1};
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

std::string NEMCUser::getUsername() const {
	throw NEMCError{"Stubbed"};
}

void NEMCUser::setUsername(std::string const& username) const {
	return;
}

std::pair<std::string, std::string> NEMCUser::doImpact(std::string const& serverCode, std::string const& serverPasscode, std::string const& clientKey, std::string const& username) const {
	throw NEMCError{"Failed authenticating to server",-1};
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