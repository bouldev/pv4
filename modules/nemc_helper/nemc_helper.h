#pragma once
#define NEMC_HELPER_PRIVATE_HEADER_INCLUDED
#include <bsoncxx/document/element.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/builder/stream/array.hpp>
#include <variant>
#include <optional>

struct NEMCError {
	std::string description;
	int translation=-1;
};

class NEMCUser {
private:
	std::string some_secret;
	
	bsoncxx::array::value stored_arr_value = bsoncxx::builder::stream::array{}<<bsoncxx::builder::stream::finalize;
public:
	NEMCUser() { };
	NEMCUser(bsoncxx::document::element const& userInfo);
	operator bsoncxx::array::view();
	
	bool isLoggedIn() const;
	std::variant<std::string, NEMCError> getUsername() const;
	std::optional<NEMCError> setUsername(std::string const& username) const;
	std::variant<std::pair<std::string, std::string>, NEMCError> doImpact(std::string const& serverCode, std::string const& serverPasscode, std::string const& clientKey, std::string const& username) const;
	inline std::string getUID() const { return "0"; };
	
	bool operator==(NEMCUser const& value) const;
	
	friend class NEMCUserAuthInfo;
};

class NEMCUserAuthInfo {
private:
	// Define your own secrets here.
	std::string some_secret;
public:
	std::string verify_url="https://google.com";
private:
	bsoncxx::array::value stored_arr_value = bsoncxx::builder::stream::array{}<<bsoncxx::builder::stream::finalize;
public:
	NEMCUserAuthInfo() { };
	NEMCUserAuthInfo(bsoncxx::document::element const& authInfo);
	operator bsoncxx::array::view();
	std::variant<std::string, NEMCError> getJitsuMeiAddress() const;
	std::variant<NEMCUser, NEMCError> auth() const;
	
	bool operator==(NEMCUserAuthInfo const& value) const;
	
	static std::variant<NEMCUserAuthInfo, NEMCError> createGuest();
	static std::variant<NEMCUserAuthInfo, NEMCError> createGuest(NEMCUserAuthInfo const& device);
};

std::string NEMCCalculateStartType(std::string const& content, std::string const& uid);