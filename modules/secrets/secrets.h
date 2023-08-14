#pragma once

#if !__has_include("../private/secrets/secrets.h")

#include <string>
#include <fmt/format.h>

class Secrets {
public:
	static std::string addSalt(std::string const& original) {
		return original;
	}
	
	static const unsigned char *getCv4Key() {
		// PLEASE, GENERATE A RSA KEY, AND PASTE IT BELOW.
		return (const unsigned char *)"";
	}
	
	static std::string get_stripe_key() {
		if(getenv("DEBUG")) {
			return "sk_test_";
		}
		return "sk_live_";
	}
	
	static std::string get_stripe_webhook_secret() {
		if(getenv("DEBUG")) {
			return "whsec_";
		}
		return "whsec_";
	}
	
	static std::string get_telegram_bot_token() {
		return "bot:";
	}
	
	static int64_t get_telegram_chat_id() {
		return -0;
	}
	
	static std::string get_telegram_webhook_secret() {
		return "123";
	}
	
	static std::string add_external_bot_salt(std::string const& original) {
		return original;
	}
};

static const unsigned char *_fbtoken_iv=(unsigned char*)"1234567890abcdef";
static const unsigned char *_fbtoken_key=(unsigned char*)"0123456789abcdefghijklmnopqrstuv";

#else

#include "../private/secrets/secrets.h"

#endif