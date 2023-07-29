#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "cpp-httplib/httplib.h"
#include "../action_core/action.h"
#include "whitelist.h"
#include "../../utils.h"
#include "../secrets/secrets.h"
#include "../products/products.h"
#include <memory>
#include <thread>
#include <shared_mutex>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <execinfo.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include "Captcha.h"
// No extern "C" for those 2 below, as they're going to be built by g++ instead of gcc
#include "cotp/cotp.h"
#include "cotp/otpuri.h"
#include "qrcode/qrcode.h"
#include <openssl/hmac.h>

#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/array.hpp>

#define RATE_LIMIT_VALUE 16

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;

extern mongocxx::pool mongodb_pool;

static httplib::Client stripeClient("https://api.stripe.com");
static httplib::Client openaiClient("https://api.openai.com");
std::string get_check_num(std::string const& data);

struct OTPDataPack {
	char secret[17];
	OTPData data;
};

namespace FBUC {
	struct PaymentIntent;
	struct UserSession {
		std::shared_ptr<FBWhitelist::User> user;
		std::string session_id;
		std::string last_captcha;
		bool token_login;
		std::vector<Product *> cart;
		std::shared_ptr<PaymentIntent> payment_intent;
		//PaymentIntent *payment_intent=nullptr;
		bool login_2fa;
		std::shared_ptr<OTPDataPack> tmp_otp;
		time_t last_alive;
		bool phoenix_only=false;
		std::string ip_address;
		std::mutex op_lock;
		
		bool verifyCaptcha(std::string const& captcha_value);
	};
	
	struct PaymentIntent {
		std::weak_ptr<UserSession> session;
		unsigned int price=0;
		unsigned int helper_price=0;
		unsigned int stripe_price=0;
		std::vector<Product *> content;
		bool needs_verify=false;
		bool banned_from_payment=false;
		bool card_only=false;
		bool approved=false;
		bool paired=false;
		std::string pairee;
		std::string stripe_pid;
	};
};

bool FBUC::UserSession::verifyCaptcha(std::string const& captcha_value) {
	if(!last_captcha.length())
		return false;
	bool ret=last_captcha==captcha_value;
	last_captcha="";
	return ret;
}

class FBUCActionCluster {
	int type;
	std::vector<std::string> actions;
public:
	FBUCActionCluster(int type, std::unordered_map<std::string, FBUC::Action *> const&);
	~FBUCActionCluster();
};

std::unordered_map<std::string, FBUC::Action *> fbuc_actions;
std::unordered_map<std::string, FBUC::Action *> fbuc_administrative_actions;

static std::unordered_map<std::string, FBUC::Action *> &select_action_set(int id) {
	if(id==0) {
		return fbuc_actions;
	}else if(id==1) {
		return fbuc_administrative_actions;
	}else{
		throw std::runtime_error("Unknown action set ID");
	}
}

FBUCActionCluster::FBUCActionCluster(int type, std::unordered_map<std::string, FBUC::Action *> const& assigning_map) {
	this->type=type;
	auto &h_map=select_action_set(type);
	for(auto const &i:assigning_map) {
		h_map[i.first]=i.second;
		actions.push_back(i.first);
	}
}

FBUCActionCluster::~FBUCActionCluster() {
	auto &h_map=select_action_set(type);
	for(auto const& i:actions) {
		delete h_map[i];
		h_map.erase(i);
	}
}

std::unordered_map<std::string, std::shared_ptr<FBUC::UserSession>> userlist;
std::shared_mutex userlist_mutex;
std::unordered_map<std::string, std::shared_ptr<FBUC::PaymentIntent>> payment_intents;
std::shared_mutex payments_mutex;

template <typename T>
bool FBUC::ActionArgument<T>::parse(Json::Value const& input) {
	if constexpr(std::is_same<T, std::string>::value) {
		if(!input[argument_name].isString()) {
			return false;
		}
		value=input[argument_name].asString();
	}else if constexpr(std::is_same<T, uint32_t>::value) {
		if(!input[argument_name].isUInt()) {
			return false;
		}
		value=input[argument_name].asUInt();
	}else if constexpr(std::is_same<T, uint64_t>::value) {
		if(!input[argument_name].isUInt64()) {
			return false;
		}
		value=input[argument_name].asUInt64();
	}else if constexpr(std::is_same<T, int32_t>::value) {
		if(!input[argument_name].isInt()) {
			return false;
		}
		value=input[argument_name].asInt();
	}else if constexpr(std::is_same<T, int64_t>::value) {
		if(!input[argument_name].isInt64()) {
			return false;
		}
		value=input[argument_name].asInt64();
	}else if constexpr(std::is_same<T, std::optional<bool>>::value) {
		if(!input[argument_name].isBool()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asBool();
	}else if constexpr(std::is_same<T, bool>::value) {
		if(!input[argument_name].isBool()) {
			return false;
		}
		value=input[argument_name].asBool();
	}else if constexpr(std::is_same<T, std::optional<FBWhitelist::User>>::value) {
		if(!input[argument_name].isString()) {
			value=std::nullopt;
			return true;
		}
		value=FBWhitelist::Whitelist::findUser(input[argument_name].asString());
	}else if constexpr(std::is_same<T, FBWhitelist::User>::value) {
		if(!input[argument_name].isString())
			return false;
		auto possiblyUser=FBWhitelist::Whitelist::findUser(input[argument_name].asString());
		if(!possiblyUser.has_value())
			return false;
		value=*possiblyUser;
	}else if constexpr(std::is_same<T, std::optional<std::string>>::value) {
		if(!input[argument_name].isString()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asString();
	}else if constexpr(std::is_same<T, std::optional<uint32_t>>::value) {
		if(!input[argument_name].isUInt()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asUInt();
	}else if constexpr(std::is_same<T, std::optional<uint64_t>>::value) {
		if(!input[argument_name].isUInt64()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asUInt64();
	}else if constexpr(std::is_same<T, std::optional<int32_t>>::value) {
		if(!input[argument_name].isInt()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asInt();
	}else if constexpr(std::is_same<T, std::optional<int64_t>>::value) {
		if(!input[argument_name].isInt64()) {
			value=std::nullopt;
			return true;
		}
		value=input[argument_name].asInt64();
	}else if constexpr(std::is_same<T, std::shared_ptr<FBUC::UserSession>>::value) {
		if(!input[argument_name].isString()) {
			value=nullptr;
			return false;
		}
		userlist_mutex.lock_shared();
		value=userlist[input[argument_name].asString()];
		userlist_mutex.unlock_shared();
		return true;
	}else{
		throw std::runtime_error("FBUC::ActionArgument: type not accepted");
	}
	return true;
}

template<typename ...Args>
void FBUC::ActionResult::parseAdditionalItems(std::string const& key, Json::Value val, Args&& ...args) {
	additional_items[key]=val;
	parseAdditionalItems(std::forward<Args>(args)...);
}

template<typename ...Args>
FBUC::ActionResult::ActionResult(bool stat, std::string const& message, Args&& ...args) {
	success=stat;
	this->message=message;
	parseAdditionalItems(std::forward<Args>(args)...);
}

template <typename T>
FBUC::ActionArgumentInternal *FBUC::ActionArgument<T>::copy() const {
	return (FBUC::ActionArgumentInternal *)new FBUC::ActionArgument<T>(argument_name);
}

class AuthConnection {
public:
	AuthConnection();
	~AuthConnection();
};

int hmac_algo_sha1(const char* byte_secret, const char* byte_string, char* out) {
	unsigned int len = 20;
	unsigned char* result = HMAC(EVP_sha1(),(unsigned char*)byte_secret, 10, (unsigned char*)byte_string, 8, (unsigned char*)out,&len);
	return result == 0 ? 0 : len;
}

int hmac_algo_sha256(const char* byte_secret, const char* byte_string, char* out) {
	unsigned int len = 32;
	unsigned char* result = HMAC(EVP_sha256(),(unsigned char*)byte_secret, 10, (unsigned char*)byte_string, 8, (unsigned char*)out,&len);
	return result == 0 ? 0 : len;
}

int hmac_algo_sha512(const char* byte_secret, const char* byte_string, char* out) {
	unsigned int len = 64;
	unsigned char* result = HMAC(EVP_sha512(),(unsigned char*)byte_secret, 10, (unsigned char*)byte_string, 8, (unsigned char*)out,&len);
	return result == 0 ? 0 : len;
}

uint64_t get_current_time() {
	using namespace std::chrono;
	auto now = system_clock::now();
	auto dur = now.time_since_epoch();
	return duration_cast<std::chrono::seconds>(dur).count();
}

namespace FBUC {
	struct ErrorDemand {
		std::string stack_dump;
		std::string error_message;
		ErrorDemand(std::string const& error_message) {
			this->error_message=error_message;
			void *addrlist[64];
			int addrlen=backtrace(addrlist, 64);
			if(!addrlen) {
				stack_dump="SHOOT, STACK IS RUINED!";
				return;
			}
			std::string stack_dump_str;
			Dl_info c_dl_info;
			for(int i=0;i<addrlen;i++) {
				void *dl_handle;
				if(dladdr1(addrlist[i], &c_dl_info, &dl_handle, RTLD_DL_LINKMAP)==0) {
					stack_dump_str+=fmt::format("#{}: [{:#x}:dladdr() failed]\n", i, (uint64_t)addrlist[i]);
					continue;
				}
				if(!c_dl_info.dli_sname) {
					c_dl_info.dli_sname="0";
				}
				if(!c_dl_info.dli_fname) {
					c_dl_info.dli_fname="???";
				}
				int demangling_status;
				char *symbol_name=abi::__cxa_demangle(c_dl_info.dli_sname, 0, 0, &demangling_status);
				if(demangling_status!=0) {
					symbol_name=(char *)c_dl_info.dli_sname;
				}
				std::string module_name="";
				if(module_name.length()!=0) {
					stack_dump_str+=fmt::format("#{}: {}+{:#x} ([{}]:{}+{:#x})\n", i, symbol_name, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_saddr, module_name, c_dl_info.dli_fname, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_fbase);
				}else{
					stack_dump_str+=fmt::format("#{}: {}+{:#x} ({}+{:#x})\n", i, symbol_name, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_saddr, c_dl_info.dli_fname, (uint64_t)addrlist[i]-(uint64_t)c_dl_info.dli_fbase);
				}
				if(demangling_status==0)
					free(symbol_name);
			}
			stack_dump=stack_dump_str;
		}
		
		virtual std::string error_name() const=0;
		virtual int status() const=0;
		virtual std::string print_with_stack_dump() const {
			return fmt::format("{} {}\n\n{}\n\n==== Stack dump ====\n{}", status(), error_name(), error_message, stack_dump);
		}
	};
	
	struct RedirectDemand {
		std::string target;
	};
	struct InvalidRequestDemand : ErrorDemand {
		InvalidRequestDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const {
			return 400;
		}
		virtual std::string error_name() const {
			return "Invalid Request";
		}
	};
	struct AccessDeniedDemand : ErrorDemand {
		AccessDeniedDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const {
			return 403;
		}
		virtual std::string error_name() const {
			return "Access Denied";
		}
	};
	struct UnauthorizedDemand : ErrorDemand {
		UnauthorizedDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const {
			return 401;
		}
		virtual std::string error_name() const {
			return "Unauthorized";
		}
	};
	struct ServerErrorDemand : ErrorDemand {
		ServerErrorDemand(std::string const& err) : ErrorDemand(err) {}
		virtual int status() const {
			return 500;
		}
		virtual std::string error_name() const {
			return "Server Exception";
		}
	};
	struct DirectReturnDemand {
		std::string content;
		std::string type;
		std::string disposition;
	};
	typedef std::shared_ptr<FBUC::UserSession> Session;
	
	void finalizePaymentIntent(std::shared_ptr<FBUC::PaymentIntent> intent, FBWhitelist::User *user, std::string const& helper_name) {
		auto pSession=intent->session.lock();
		if(pSession) {
			pSession->cart.clear();
		}
		std::string desc;
		Json::Value descContent(Json::arrayValue);
		for(Product *i:intent->content) {
			i->execute_on(*user);
			desc+=fmt::format("{}:{} - {} CNY\n", i->product_id(), i->product_name(), i->price());
			descContent.append(i->toJSON());
		}
		intent->paired=true;
		intent->approved=true;
		auto client=mongodb_pool.acquire();
		(*client)["fastbuilder"]["payments"].insert_one(document{}<<"username"<<user->username<<"price"<<(int32_t)intent->price<<"helper_price"<<(int32_t)intent->helper_price<<"helper"<<helper_name<<"content"<<Utils::writeJSON(descContent)<<"description"<<desc<<"date"<<bsoncxx::types::b_date(std::chrono::milliseconds{time(nullptr)*1000})<<finalize);
		
	}

	ACTION2(APIListAction, "api",
			std::optional<std::string>, with_prefix, "with_prefix",
			std::optional<std::string>, jump_to, "jump_to") {
		std::string prefix=with_prefix->has_value()?**with_prefix:"";
		struct ActionResult result={true, "ok"};
		bool include_login_only=(bool)session->user;
		for(auto const &i:fbuc_actions) {
			if(include_login_only||!i.second->mandatory_login()) {
				result.additional_items[i.second->action_name]=fmt::format("{}/api/{}", prefix, i.second->action_name);
			}
		}
		if(jump_to->has_value()) {
			if(result.additional_items[**jump_to]) {
				throw RedirectDemand{result.additional_items[**jump_to].asString()};
			}else{
				return {false, "No such entry to jump to."};
			}
		}
		if(session->user&&session->user->isAdministrator) {
			Json::Value ext_map;
			for(auto const &i:fbuc_administrative_actions) {
				ext_map[i.second->action_name]=fmt::format("{}/api/administrative/{}", prefix, i.second->action_name);
			}
			result.additional_items["ext"]=ext_map;
		}
		if(session->user) {
			result.additional_items["username"]=*session->user->username;
			result.additional_items["theme"]=session->user->preferredtheme.has_value()?*session->user->preferredtheme:"bootstrap";
		}
		return result;
	}
	
	ACTION3(LoginAction, "login",
			std::optional<std::string>, _username, "username",
			std::optional<std::string>, _password, "password",
			std::optional<std::string>, token, "token") {
		if(session->user) {
			throw InvalidRequestDemand{"Already logged in"};
		}
		std::string username;
		std::string password;
		std::string unsaltedPassword="impossible";
		if(!token->has_value()) {
			if(!_username->has_value()||!_password->has_value()) {
				throw InvalidRequestDemand{"Insufficient arguments"};
			}
			username=**_username;
			unsaltedPassword=**_password;
			password=Utils::sha256(Secrets::addSalt(**_password));
		}else{
			if(_username->has_value()) {
				throw InvalidRequestDemand{"Conflicted arguments"};
			}
			Json::Value token_content;
			bool parsed=Utils::parseJSON(FBToken::decrypt(**token), &token_content, nullptr);
			if(!parsed||!token_content["username"].isString()||!token_content["password"].isString()||!token_content["newToken"].asBool()) {
				return {false, "Invalid token"};
			}
			username=token_content["username"].asString();
			password=token_content["password"].asString();
		}
		std::optional<FBWhitelist::User> pUser=FBWhitelist::Whitelist::findUser(username);
		if(pUser->password==unsaltedPassword)
			pUser->password=Utils::sha256(Secrets::addSalt(unsaltedPassword));
		if(!pUser.has_value()||pUser->password!=password) {
			SPDLOG_INFO("User Center login (rejected): Username: {}, IP: {}", username, session->ip_address);
			return {false, "Invalid username or password"};
		}
		session->user=std::make_shared<FBWhitelist::User>(*pUser);
		std::string user_theme=pUser->preferredtheme.has_value()?(*pUser->preferredtheme):"bootstrap";
		session->token_login=token->has_value();
		session->phoenix_only=false;
		if(session->login_2fa=pUser->two_factor_authentication_secret.has_value()) {
			if(pUser->two_factor_authentication_secret->length()!=15) {
				OTPDataPack *otpdata=new OTPDataPack;
				strcpy(otpdata->secret, pUser->two_factor_authentication_secret->c_str());
				session->tmp_otp=std::shared_ptr<OTPDataPack>(otpdata);
				totp_new(&(otpdata->data), otpdata->secret, hmac_algo_sha1, get_current_time, 6, 30);
			}else{
				session->login_2fa=false;
			}
		}
		*pUser->keep_reference=true;
		SPDLOG_INFO("User Center login (passed): Username: {}, IP: {}", username, session->ip_address);
		return {true, "Welcome", "theme", user_theme, "isadmin", *pUser->isAdministrator};
	}
	
	ACTION0(UCCaptchaAction, "captcha") {
		std::vector<uint8_t> buf;
		std::string the_captcha;
		if(generateCaptcha(buf, the_captcha)!=0) {
			throw ServerErrorDemand{"Unknown error"};
		}
		session->last_captcha=the_captcha;
		throw DirectReturnDemand {
			std::string((const char *)&buf.front(), buf.size()),
			"image/png"
		};
	}
	
	LACTION0(FetchAnnouncementsAction, "fetch_announcements") {
		if(session->login_2fa) {
			return {false, "2FA is required", "is_2fa", true};
		}
		Json::Value outvalues(Json::arrayValue);
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto cursor=fbdb["announcements"].find(document{}<<finalize, mongocxx::options::find{}.limit(10).sort(document{}<<"_id"<<-1<<finalize));
		for(auto &i:cursor) {
			Json::Value cur;
			cur["title"]=(std::string)i["title"].get_string();
			cur["content"]=(std::string)i["content"].get_string();
			cur["date"]=(std::string)i["date"].get_string();
			cur["author"]=(std::string)i["author"].get_string();
			cur["uniqueId"]=(std::string)i["uniqueId"].get_string();
			if(i["upvoters"]) {
				cur["upvotes"]=std::distance(i["upvoters"].get_array().value.begin(),i["upvoters"].get_array().value.end());
			}else{
				cur["upvotes"]=0;
			}
			if(i["downvoters"]) {
				cur["downvotes"]=std::distance(i["downvoters"].get_array().value.begin(),i["downvoters"].get_array().value.end());
			}else{
				cur["downvotes"]=0;
			}
			outvalues.append(cur);
		}
		throw DirectReturnDemand{Utils::writeJSON(outvalues), "application/json"};
	}
	
	LACTION0(UCLogoutAction, "logout") {
		userlist_mutex.lock();
		*session->user->keep_reference=false;
		userlist.erase(session->session_id);
		userlist_mutex.unlock();
		return {true, "OK"};
	}
	
	LACTION0(FetchProfileAction, "fetch_profile") {
		FBWhitelist::User user=*session->user;
		std::string blc="机器人绑定码在 Token 登录状态下不能被显示。";
		if(!session->token_login) {
			blc=fmt::format("v|{}!{}", *(user.username), Utils::sha256(fmt::format("v|{}b4$9v",*(user.username))));
		}
		std::string cn_username=user.cn_username.has_value()?*(user.cn_username):"";
		Json::Value slots=user.rentalservers.toDescriptiveJSON();
		bool is_2fa=user.two_factor_authentication_secret.has_value();
		float mp_duration;
		if(!session->user->free) {
			mp_duration=-1;
		}else if(!session->user->expiration_date.stillAlive()) {
			mp_duration=0;
		}else{
			mp_duration=round(((session->user->expiration_date-time(nullptr))/86400.00)*100.0)/100.0;
		}
		return {true, "Well done", "blc", blc, "cn_username", cn_username, "slots", slots, "is_2fa", is_2fa, "monthly_plan_duration", mp_duration, "is_rate_limited", *session->user->rate_limit_counter>=RATE_LIMIT_VALUE};
	}
	
	LACTION0(UCGetHelperStatusAction, "get_helper_status") {
		FBWhitelist::User *user=session->user.get();
		if(!user->nemc_access_info.has_value()||!user->nemc_access_info->has_user()||(user->free&&!user->expiration_date.stillAlive())) {
			return {true, "success", "set", false};
		}
		std::string un="???";
		try {
			NEMCUser nemcUser;
			if(user->nemc_temp_info.has_value()) {
				nemcUser=user->nemc_temp_info;
			}
			if(!nemcUser.isLoggedIn()) {
				auto pud=user->nemc_access_info->auth();
				if(std::holds_alternative<NEMCError>(pud)) {
					if(std::get<NEMCError>(pud).translation==-2) {
						auto addr=user->nemc_access_info->getJitsuMeiAddress();
						if(std::holds_alternative<NEMCError>(addr)) {
							return {false, "Identification verification is required, but failed to get address."};
						}
						return {true, "ok", "set", true, "need_realname", true, "realname_addr", std::get<std::string>(addr)};
					}
					throw std::runtime_error(std::get<NEMCError>(pud).description);
				}
				nemcUser=std::get<NEMCUser>(pud);
				user->nemc_temp_info=nemcUser;
			}
			auto pun=nemcUser.getUsername();
			if(std::holds_alternative<NEMCError>(pun)) {
				throw std::runtime_error(std::get<NEMCError>(pun).description);
			}
			un=std::get<std::string>(pun);
		}catch(std::exception const& err) {
			SPDLOG_DEBUG("GetHelperStatus: Error: {}", err.what());
		}
		return {true, "ok", "set", true, "need_realname", false, "username", un};
	}
	
	LACTION1(SaveClientUsernameAction, "save_client_username",
			std::string, username, "cnun") {
		if(username->length()>32) {
			return {false, "用户名太长"};
		}
		session->user->cn_username=*username;
		return {true, "", "username", *username};
	}
	
	LACTION3(SaveSlotAction, "save_slot",
			std::string, slotid, "slotid",
			std::optional<std::string>, content, "content",
			std::optional<std::string>, operation, "operation") {
		FBWhitelist::User *user=session->user.get();
		if(!user->rentalservers.size()) {
			throw InvalidRequestDemand{"NO WAY"};
		}
		auto &slot=user->rentalservers[slotid];
		if(!slot) {
			return {false, "内部错误: slotid 无效"};
		}
		if(!content->has_value()&&**operation!="remove") {
			throw InvalidRequestDemand{"Invalid request"};
		}
		if(**operation!="remove") {
			std::string scontent=**content;
			if(scontent.length()>16||scontent.length()<4) {
				return {false, "过于夸张的租赁服号长度"};
			}
			uint32_t val=0;
			try {
				val=std::stoi(scontent);
			}catch(...) {
				return {false, "无效租赁服号"};
			}
			if(slot.lastdate) {
				if(slot.locked) {
					return {false, "不可以更改已经写入的固定 slot"};
				}
				time_t sugosu=time(nullptr)-slot.lastdate;
				if(sugosu<=2592000) {
					float ato=round(((2592000-sugosu)/86400.0)*100.0)/100.0;
					return {false, fmt::format("{} 天之后方可修改此 slot", ato)};
				}
			}
			slot.lastdate=time(nullptr);
			slot.content=scontent;
			return {true, "Well done", "slots", user->rentalservers.toDescriptiveJSON()};
		}else{
			user->rentalservers.erase_slot(slotid);
			return {true, "ok", "slots", user->rentalservers.toDescriptiveJSON()};
		}
	}
	
	LACTION1(UCHelperOperationAction, "helper_operation",
			std::optional<std::string>, username, "username") {
		FBWhitelist::User *user=session->user.get();
		if(user->free&&!user->expiration_date.stillAlive()) {
			return {false, "月额 Plan 未激活"};
		}
		if(username->has_value()) {
			if((*username)->length()<6||(*username)->length()>16) {
				return {false, "辅助用户 昵称长度不得少于 7 字符或长于 16 字符。"};
			}
		}
		try {
			NEMCUser nemcUser;
			if(!user->nemc_access_info.has_value()||!user->nemc_access_info->has_user()) {
				NEMCUserAuthInfo authInfo;
				if(user->nemc_access_info.has_value()&&!user->nemc_access_info->has_user()) {
					auto authInfo_opt=NEMCUserAuthInfo::createGuest(*user->nemc_access_info);
						if(std::holds_alternative<NEMCError>(authInfo_opt)) {
						return {false, "Failed to create guest"};
					}
					authInfo=std::get<NEMCUserAuthInfo>(authInfo_opt);
				}else{
					auto authInfo_opt=NEMCUserAuthInfo::createGuest();
					if(std::holds_alternative<NEMCError>(authInfo_opt)) {
						return {false, "Failed to create guest"};
					}
					authInfo=std::get<NEMCUserAuthInfo>(authInfo_opt);
				}
				user->nemc_access_info=authInfo;
				if(!authInfo.has_user()&&authInfo.verify_url.size()) {
					return {false, "请按指示完成网易验证码验证后再试", "verify_url", authInfo.verify_url};
				}
				auto user_opt=authInfo.auth();
				if(std::holds_alternative<NEMCError>(user_opt)) {
					NEMCError err=std::get<NEMCError>(user_opt);
					if(err.translation==-2) {
						return {false, fmt::format("Failed to authenticate: {}", err.description), "need_realname", true};
					}
					return {false, fmt::format("Failed to authenticate: {}", err.description)};
				}
				nemcUser=std::get<NEMCUser>(user_opt);
				user->nemc_temp_info=nemcUser;
			}else{
				if(user->nemc_temp_info.has_value()) {
					nemcUser=user->nemc_temp_info;
				}
				if(!nemcUser.isLoggedIn()) {
					auto uo=user->nemc_access_info->auth();
					if(std::holds_alternative<NEMCError>(uo)) {
						NEMCError err=std::get<NEMCError>(uo);
						return {false, fmt::format("Failed to authenticate to server: {}", err.description)};
					}
					nemcUser=std::get<NEMCUser>(uo);
					user->nemc_temp_info=nemcUser;
				}
			}
			auto err=nemcUser.setUsername(**username);
			if(err.has_value()) {
				NEMCError error_val=*err;
				return {false, fmt::format("Failed to set username: {}", error_val.description)};
			}
		}catch(std::exception const& err) {
			return {false, "Unknown exception occured"};
		}
		return {true, "ok"};
	}
	
	LACTION0(UCGetProductListAction, "get_product_list") {
		FBWhitelist::User &user=*session->user;
		std::vector<Product *> const& products=all_products();
		Json::Value product_list(Json::arrayValue);
		for(Product *i:products) {
			if(!i->check_on(user))
				continue;
			product_list.append(i->toJSON());
		}
		return {true,"","products",product_list};
	}
	
	LACTION1(AddProductToCartAction, "add_product_to_cart",
			std::string, _product_id, "product_id") {
		unsigned int product_id=std::stoi(_product_id);
		Product *target=nullptr;
		std::vector<Product *> const& products=all_products();
		for(Product *i:products) {
			if(i->product_id()==product_id) {
				target=i;
				break;
			}
		}
		if(!target) {
			return {false, "未找到商品"};
		}
		if(!target->check_on(*session->user)) {
			return {false, "你未满足购买此商品的所需条件"};
		}
		if(target->forbid_cart()) {
			return {false, "商品禁止加入购物车。"};
		}
		if(target->no_multi_add()) {
			for(Product *i:session->cart) {
				if(i==target) {
					return {false, "商品已在购物车"};
				}
			}
		}
		session->cart.push_back(target);
		return {true, ""};
	}
	
	LACTION0(GetShoppingCartAction, "get_shopping_cart") {
		Json::Value ret_val(Json::arrayValue);
		for(Product *i:session->cart) {
			ret_val.append(i->toJSON());
		}
		throw DirectReturnDemand{Utils::writeJSON(ret_val), "application/json"};
	}
	
	LACTION1(EraseFromShoppingCartAction, "erase_from_shopping_cart",
			std::string, _product_id, "product_id") {
		uint32_t product_id=std::stoi(_product_id);
		for(std::vector<Product *>::iterator it=session->cart.begin(); it!=session->cart.end();) {
			if((*it)->product_id()==product_id) {
				it=session->cart.erase(it);
				// Erase only one
				break;
			}else{
				it++;
			}
		}
		return {true, ""};
	}
	
	LACTION0(GenerateBillAction, "generate_bill") {
		if(!session->cart.size()) {
			return {false, "购物车里没有商品"};
		}
		FBUC::PaymentIntent *currentPaymentIntent=new FBUC::PaymentIntent;
		currentPaymentIntent->session=session;
		if(session->user->banned_from_payment) {
			currentPaymentIntent->banned_from_payment=true;
		}else{
			currentPaymentIntent->needs_verify=false;
			//currentPaymentIntent->needs_verify=!session->user->payment_verify_fingerprint.has_value();
		}
		for(Product *i:session->cart) {
			currentPaymentIntent->content.push_back(i);
			if(i->card_only()) {
				currentPaymentIntent->card_only=true;
			}
			currentPaymentIntent->price+=i->price();
			if((unsigned int)i->price()*0.8==0&&i->price()!=0) {
				currentPaymentIntent->helper_price+=1;
			}else{
				currentPaymentIntent->helper_price+=i->price()*0.8;
			}
		}
		if(currentPaymentIntent->price<6) {
			currentPaymentIntent->stripe_price=6;
		}else{
			currentPaymentIntent->stripe_price=currentPaymentIntent->price;
		}
		auto ptr=std::shared_ptr<FBUC::PaymentIntent>(currentPaymentIntent);
		payments_mutex.lock();
		payment_intents[session->user->username]=ptr;
		payments_mutex.unlock();
		session->payment_intent=ptr;
		return {true, "", "location", "/pay"};
	}
	
	LACTION1(GetBillAction, "get_bill",
			Session, session, "secret") {
		if(!session->payment_intent) {
			return {false, "", "show", "未找到交易或交易已完成"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent=session->payment_intent;
		std::string show;
		for(Product *sub:intent->content) {
			if(sub->card_only()) {
				show+="[仅官方支付] ";
			}
			show+=fmt::format("{}: ￥{}\n", sub->product_name(), sub->price());
		}
		show+=fmt::format("\n<b>合计</b>: ￥{}\n",intent->price?std::to_string(intent->price):"免费");
		if(intent->stripe_price!=intent->price&&intent->price!=0) {
			show+=fmt::format("官方支付最低价: ￥{}\n", intent->stripe_price);
		}
		if(intent->card_only) {
			show+="注意：含有仅官方支付商品。\n";
		}
		if(intent->banned_from_payment) {
			show+="<hr/><b style=\"color:red;\">由于您的支付信息与他人出现重合，此账户已被永久禁止支付，其他功能不受影响。</b>";
		}
		if(intent->needs_verify) {
			show+="<hr/><b style=\"color:blue;\">由于我们需要验证您的账户唯一性，本次支付只能使用本页面上的支付方式完成。</b>\n";
		}
		if(getenv("DEBUG")) {
			show+="\n\n<b style=\"color:red;\">调试模式</b>";
			return {true,"", "show", show, "codepwn_pay_available", false, "isfree", intent->helper_price==0&&intent->price==0, "can_use_point", false, "needs_verify", intent->needs_verify,
				"test_key", "pk_test_51MKodeE2lNjB2a2N3DSkPh20JkjjOAAVlHKK5bIRtPYeDmKCeseyP0phJbEPx9vKA4W6ovF4ziXPAJ0MOFx5fxW200LwFqAsGk"};
		}
		return {true, "", "show", show, "codepwn_pay_available", false, "isfree", intent->helper_price==0&&intent->price==0, "can_use_point", false, "needs_verify", intent->needs_verify};
	}
	
	LACTION0(CheckPaymentAction, "check_payment") {
		std::shared_ptr<FBUC::PaymentIntent> intent=session->payment_intent;
		if(!intent) {
			return {false, "会话已经过期", "expired", true};
		}
		if(!intent->paired||!intent->approved) {
			return {false, "尚未确认", "paired", intent->paired, "price", intent->price};
		}
		return {true, "Well done", "paired", true, "approved", true};
	}
	
	LACTION0(UCGetBalanceAction, "get_balance") {
		Json::Value ret;
		if(session->user->promocode_count.has_value()) {
			ret.append(*session->user->promocode_count);
		}else{
			ret.append(0);
		}
		ret.append(0);
		ret.append(0);
		throw DirectReturnDemand{Utils::writeJSON(ret), "application/json"};
	}
	
	LACTION1(PairPaymentAction, "pair_payment",
			std::string, identifier, "number") {
		payments_mutex.lock_shared();
		if(!payment_intents.contains(identifier)) {
			payments_mutex.unlock_shared();
			return {false, "确认码或用户名无效"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent=payment_intents[identifier];
		payments_mutex.unlock_shared();
		if(intent->needs_verify) {
			return {false, "用户需要完成一次官方支付以满足唯一性验证需求"};
		}else if(intent->paired) {
			return {false, "指定确认码已然匹配，请让用户重新结算。"};
		}else if(intent->card_only) {
			return {false, "支付中存在仅官方支付商品，不能使用此方法结帐"};
		}
		if(*session->user->promocode_count<=0) {
			return {false, "余额不足"};
		}
		std::string list;
		for(Product *i:intent->content) {
			list+=fmt::format("{}: ￥{}<br/>", i->product_name(), i->price());
		}
		list+=fmt::format("用户价格合计: ￥{}<br/>代理价合计: ￥{}<br/>", intent->price, intent->helper_price);
		if(*session->user->promocode_count<intent->helper_price) {
			return {false, "未确认。交易不能完成，因为余额不足。","list", list};
		}
		intent->paired=true;
		intent->pairee=session->user->username;
		return {true,"","list",list};
	}
	
	LACTION1(ApprovePaymentAction, "approve_payment",
			std::string, identifier, "number") {
		payments_mutex.lock_shared();
		if(!payment_intents.contains(identifier)) {
			payments_mutex.unlock_shared();
			return {false, "确认码无效"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent=payment_intents[identifier];
		payments_mutex.unlock_shared();
		if(intent->needs_verify) {
			return {false, "用户需要完成一次官方支付以满足唯一性验证需求"};
		}else if(intent->card_only) {
			return {false, "支付中存在仅官方支付商品，不能使用此方法结帐"};
		}else if(intent->banned_from_payment) {
			throw InvalidRequestDemand{"Payment-banned user"};
		}
		int64_t final=session->user->promocode_count-intent->helper_price;
		if(final<0) {
			return {false, "余额不足"};
		}
		std::shared_ptr<FBUC::UserSession> targetSession=intent->session.lock();
		if(!targetSession||intent->approved) {
			return {false, "会话过期"};
		}
		session->user->promocode_count=final;
		finalizePaymentIntent(intent, targetSession->user.get(), session->user->username);
		return {true, "Well done"};
	}
	
	LACTION2(ChangePasswordAction, "change_password",
			std::string, originalPassword, "originalPassword",
			std::string, newPassword, "newPassword") {
		if(session->token_login) {
			throw InvalidRequestDemand{"Changing password is forbidden for token-login users."};
		}
		if(originalPassword->length()!=64||newPassword->length()!=64||newPassword=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
			throw InvalidRequestDemand{"Invalid Request"};
		}
		FBWhitelist::User *user=session->user.get();
		if(user->password!=Utils::sha256(Secrets::addSalt(*originalPassword))) {
			return {false, "原密码不正确"};
		}
		user->password=Utils::sha256(Secrets::addSalt(newPassword));
		return {true, "ok"};
	}
	
	LACTION0(UCCalculateMonthlyPlanDurationAction, "calculate_monthly_plan_duration") {
		if(!session->user->free) {
			return {true, "", "duration", -1};
		}else if(!session->user->expiration_date.stillAlive()) {
			return {true, "", "duration", 0};
		}
		return {true, "", "duration", round(((session->user->expiration_date-time(nullptr))/86400.00)*100.0)/100.0};
	}
	
	LACTION1(RedeemForFreeAction, "redeem_for_free",
			std::string, captcha, "captcha") {
		if(!session->verifyCaptcha(captcha)) {
			return {false, "验证码错误"};
		}
		if(!session->payment_intent) {
			return {false, "无商品"};
		}
		std::shared_ptr<FBUC::PaymentIntent> intent=session->payment_intent;
		if(intent->approved) {
			return {false, "无商品"};
		}
		if(intent->price>0||intent->helper_price>0) {
			return {false, "商品需要付费，而非免费获取"};
		}
		finalizePaymentIntent(intent, session->user.get(), "@Free");
		return {true};
	}
	
	LACTION2(UCVoteAnnouncementAction, "vote_announcement",
			std::string, vote_type, "vote_type",
			std::string, uniqueId, "unique_id") {
		if(vote_type!="up"&&vote_type!="down")
			throw InvalidRequestDemand{"无效投票类型"};
		FBWhitelist::User *user=session->user.get();
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto _target_announcement=fbdb["announcements"].find_one(document{}<<"uniqueId"<<*uniqueId<<finalize);
		if(!_target_announcement.has_value()) {
			return {false, "公告不存在"};
		}
		auto target_announcement=*_target_announcement;
		if(vote_type=="up") {
			if(target_announcement["downvoters"]) {
				auto downvoters_arr=target_announcement["downvoters"].get_array();
				for(auto i:downvoters_arr.value) {
					if(user->user_oid==(std::string)i.get_string()) {
						return {false, "你已经投过反对票了，不能投支持票。"};
					}
				}
			}
			size_t orig_upvoters=target_announcement["upvoters"]?std::distance(target_announcement["upvoters"].get_array().value.begin(),target_announcement["upvoters"].get_array().value.end()):0;
			auto pull_result=fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$pull"<<open_document<<"upvoters"<<user->user_oid<<close_document<<finalize);
			if(!pull_result->modified_count()) {
				orig_upvoters++;
				fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$push"<<open_document<<"upvoters"<<user->user_oid<<close_document<<finalize);
			}else{
				orig_upvoters--;
			}
			Json::Value update_val;
			update_val["upvotes"]=orig_upvoters;
			return {true, "ok", "update", update_val};
		}else if(vote_type=="down") {
			if(target_announcement["upvoters"]) {
				auto upvoters_arr=target_announcement["upvoters"].get_array();
				for(auto i:upvoters_arr.value) {
					if(user->user_oid==(std::string)i.get_string()) {
						return {false, "你已经投过支持票了，不能投反对票。"};
					}
				}
			}
			size_t orig_downvoters=target_announcement["downvoters"]?std::distance(target_announcement["downvoters"].get_array().value.begin(),target_announcement["downvoters"].get_array().value.end()):0;
			auto pull_result=fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$pull"<<open_document<<"downvoters"<<user->user_oid<<close_document<<finalize);
			if(!pull_result->modified_count()) {
				orig_downvoters++;
				fbdb["announcements"].update_one(document{}<<"_id"<<target_announcement["_id"].get_oid()<<finalize, document{}<<"$push"<<open_document<<"downvoters"<<user->user_oid<<close_document<<finalize);
			}else{
				orig_downvoters--;
			}
			Json::Value update_val;
			update_val["downvotes"]=orig_downvoters;
			return {true, "ok", "update", update_val};
		}
		throw ServerErrorDemand{"Fell"};
	}
	
	LACTION0(GetThemeInfoAction, "get_theme_info") {
		return {true, "", "data", *session->user->preferredtheme};
	}
	
	LACTION1(ApplyThemeAction, "apply_theme",
			std::string, theme, "name") {
		if(theme->size()<2||theme->size()>32) {
			throw InvalidRequestDemand{"Invalid theme string given"};
		}
		session->user->preferredtheme=theme;
		return {true};
	}
	
	LACTION0(StripeCreateSessionAction, "stripe_create_session") {
		std::shared_ptr<FBUC::PaymentIntent> intent=session->payment_intent;
		if(!intent||intent->approved) {
			return {false, "没有有效的支付请求"};
		}
		if(!intent->content.size()) {
			throw InvalidRequestDemand{"Invalid request"};
		}
		if(intent->banned_from_payment) {
			throw InvalidRequestDemand{"Payment request while being banned from payment"};
		}
		httplib::Params params{
			{"amount", std::to_string(intent->stripe_price*100)},
			{"currency", "cny"},
			{"payment_method_types[0]", "card"},
			{"payment_method_types[1]", "alipay"}
		};
		auto stripe_res=stripeClient.Post("/v1/payment_intents", params);
		if(!stripe_res) {
			throw ServerErrorDemand{"Unknown error"};
		}
		Json::Value stripe_parsed;
		if(!Utils::parseJSON(stripe_res->body, &stripe_parsed, nullptr)) {
			throw ServerErrorDemand{"Failed to parse stripe response"};
		}
		payments_mutex.lock();
		payment_intents[stripe_parsed["id"].asString()]=payment_intents[session->user->username];
		payments_mutex.unlock();
		intent->stripe_pid=stripe_parsed["id"].asString();
		std::string return_url="https://api.fastbuilder.pro/api/stripe_recover?ssid=";
		if(getenv("DEBUG")) {
			return_url="http://127.0.0.1:8687/api/stripe_recover?ssid=";
		}
		return_url+=session->session_id;
		return {true, "", "clientSecret", stripe_parsed["client_secret"].asString(), "return_url", return_url};
	}
	
	LACTION0(GetPaymentLogAction, "get_payment_log") {
		std::shared_ptr<FBWhitelist::User> user=session->user;
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto payments_o=fbdb["payments"].find(document{}<<"username"<<*(user->username)<<finalize);
		Json::Value ret_arr(Json::arrayValue);
		for(auto &i:payments_o) {
			std::string i_str=bsoncxx::to_json(i);
			Json::Value item_jv;
			Utils::parseJSON(i_str, &item_jv);
			uint64_t date_v=item_jv["date"]["$date"].asUInt64();
			item_jv["date"]=date_v;
			std::string description="";
			if(item_jv["refunded"].asBool()) {
				description+="<b style=\"color:red;\">[已退款]</b><br/>";
			}
			if(item_jv["helper"].isString()&&item_jv["helper"].asString()[0]=='@') {
				description+="官方支付<br/>";
			}else{
				description+=fmt::format("代理支付: {}<br/>", item_jv["helper"].asString());
			}
			Json::Value content_parsed;
			if(item_jv["content"].isString()) {
				Utils::parseJSON(item_jv["content"].asString(), &content_parsed);
			}else{
				content_parsed=item_jv["content"];
			}
			description+="<hr/><ol>";
			for(Json::Value const& sub:content_parsed) {
				description+=fmt::format("<li>{} - ￥{}</li>", sub["product_name"].asString(), sub["price"].asInt());
			}
			description+="</ol>";
			Json::Value current;
			current["identifier"]=item_jv["date"];
			current["description"]=description;
			ret_arr.insert(0, current);
		}
		return {true, "", "payments", ret_arr, "pages", 1};
	}
	
	LACTION1(GetUserContactsAction, "get_user_contacts",
			std::optional<int64_t>, identifier, "identifier") {
		std::shared_ptr<FBWhitelist::User> user=session->user;
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		if(!identifier->has_value()) {
			Json::Value ret(Json::ValueType::arrayValue);
			auto the_document=document{};
			if(!*(user->isAdministrator)) {
				the_document<<"username"<<*user->username;
			}else{
				the_document<<"closed"<<false;
			}
			auto user_contacts=fbdb["contacts"].find(the_document<<finalize);
			for(auto &i:user_contacts) {
				Json::Value current_value;
				current_value["title"]=(std::string)i["title"].get_string();
				current_value["identifier"]=(int64_t)i["identifier"].get_int64();
				if(i["closed"].get_bool()) {
					current_value["closed"]=true;
				}else{
					current_value["has_update"]=*user->isAdministrator^i["user_can_add_msg"].get_bool();
				}
				ret.insert(0, current_value);
			}
			return {true, "ok", "contacts", ret};
		}
		auto search_doc=document{};
		search_doc<<"identifier"<<**identifier;
		if(!*user->isAdministrator) {
			search_doc<<"username"<<*user->username;
		}
		auto _spec_contact=fbdb["contacts"].find_one(search_doc<<finalize);
		if(!_spec_contact.has_value()) {
			return {false, "未找到对应联络"};
		}
		auto spec_contact=*_spec_contact;
		Json::Value ret_val;
		ret_val["title"]=(std::string)spec_contact["title"].get_string();
		Json::Value thread_arr(Json::ValueType::arrayValue);
		bsoncxx::array::view thread_db_arr=(bsoncxx::array::view)spec_contact["thread"].get_array();
		for(auto &i:thread_db_arr) {
			Json::Value sub_val;
			sub_val["sender"]=(std::string)i["sender"].get_string();
			sub_val["content"]=(std::string)i["content"].get_string();
			sub_val["time"]=(int64_t)i["time"].get_int64();
			thread_arr.insert(0, sub_val);
		}
		ret_val["thread"]=thread_arr;
		ret_val["user_can_add_msg"]=*user->isAdministrator|spec_contact["user_can_add_msg"].get_bool();
		if(spec_contact["closed"].get_bool()) {
			ret_val["user_can_add_msg"]=false;
		}
		ret_val["identifier"]=(int64_t)spec_contact["identifier"].get_int64();
		return {true, "found", "item", ret_val};
	}
	
	LACTION2(CreateUserContactAction, "create_user_contact",
			std::string, title, "title",
			std::string, content, "content") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto old_contact=fbdb["contacts"].find_one(document{}<<"username"<<session->user->username<<"closed"<<false<<finalize);
		if(old_contact.has_value()) {
			return {false, "已有过去联络存在，请耐心等待，或删除对应联络。"};
		}
		if(content->length()>1000) {
			return {false, "联络内容太长"};
		}else if(title->length()>32) {
			return {false, "标题太长"};
		}
		Json::Value openai_request;
		openai_request["model"]="gpt-3.5-turbo";
		Json::Value messages_arr(Json::arrayValue);
		Json::Value first_system_notice;
		first_system_notice["role"]="system";
		first_system_notice["content"]="You should make sure the content is not harmful, and is either in English, Japanese or Chinese, and human-readable.\nContent should also be detailed and formal like user contacts, describing what problem they are having, unrelated content like \"test\" should be rejected.\nIf the requirements do not met, reply with \"REJECT\", elsewhere reply \"PASS\".";
		messages_arr.append(first_system_notice);
		Json::Value second_part;
		second_part["role"]="user";
		second_part["content"]=fmt::format("Title: {}\nContent: {}", *title, *content);
		messages_arr.append(second_part);
		openai_request["messages"]=messages_arr;
		auto openai_response=openaiClient.Post("/v1/chat/completions", Utils::writeJSON(openai_request), "application/json");
		if(!openai_response||openai_response->status!=200) {
			throw ServerErrorDemand{"OpenAI Request Failed"};
		}
		Json::Value openai_parsed;
		Utils::parseJSON(openai_response->body, &openai_parsed);
		std::string const& order=openai_parsed["choices"][0]["message"]["content"].asString();
		if(order=="REJECT") {
			return {false, "经检测，你的联络不包括有效信息，已被阻止发送。"};
		}else if(order=="HARMFUL") {
			return {false, "经检测，你的联络包含有害内容，已被阻止发送。"};
		}
		int64_t con_id=(int64_t)time(nullptr);
		fbdb["contacts"].insert_one(document{}<<"username"<<*session->user->username<<"title"<<*title<<"thread"<<open_array<<open_document<<"sender"<<*session->user->username<<"content"<<*content<<"time"<<(int64_t)time(nullptr)<<close_document<<close_array<<"closed"<<false<<"user_can_add_msg"<<false<<"identifier"<<con_id<<finalize);
		std::string tg_notification=fmt::format("*New Contact*\n!CONTACTID={}!\nUser: `{}`\nTitle: `{}`\n\n```\n{}\n```", con_id, *session->user->username, *title, *content);
		std::thread([tg_notification]() {
			httplib::Client tgClient("https://api.telegram.org");
			Json::Value postContent;
			postContent["chat_id"]=Secrets::get_telegram_chat_id();
			postContent["parse_mode"]="MarkdownV2";
			postContent["text"]=tg_notification;
			tgClient.Post(fmt::format("/{}/sendMessage", Secrets::get_telegram_bot_token()), Utils::writeJSON(postContent), "application/json");
		}).detach();
		return {true, "OK", "identifier", con_id};
	}
	
	LACTION4(UpdateUserContactAction, "update_user_contact",
			int64_t, identifier, "identifier",
			std::string, content, "content",
			std::optional<bool>, anonymous, "anonymous",
			std::optional<bool>, closing, "closing") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		auto contact_item=fbdb["contacts"].find_one(document{}<<"identifier"<<*identifier<<finalize);
		if(!contact_item.has_value()) {
			return {false, "不存在此联络"};
		}
		auto r_contact_item=*contact_item;
		if(r_contact_item["closed"].get_bool()) {
			return {false, "联络已经被关闭"};
		}
		std::string name="用户中心管理员";
		if(!session->user->isAdministrator) {
			if(((std::string)r_contact_item["username"].get_string())!=session->user->username) {
				return {false, "不存在此联络"};
			}
			if(!r_contact_item["user_can_add_msg"].get_bool()) {
				return {false, "请等待回复"};
			}
			Json::Value openai_request;
			openai_request["model"]="gpt-3.5-turbo";
			Json::Value messages_arr(Json::arrayValue);
			Json::Value first_system_notice;
			first_system_notice["role"]="system";
			first_system_notice["content"]="You should make sure the content is not harmful, and is either in English, Japanese or Chinese, and human-readable.\nContent should also be detailed and formal like user contacts, describing what problem they are having, unrelated content like \"test\" should be rejected.\nIf the requirements do not met, reply with \"REJECT\", elsewhere reply \"PASS\".";
			messages_arr.append(first_system_notice);
			Json::Value second_part;
			second_part["role"]="user";
			second_part["content"]=fmt::format("Content: {}", *content);
			messages_arr.append(second_part);
			openai_request["messages"]=messages_arr;
			auto openai_response=openaiClient.Post("/v1/chat/completions", Utils::writeJSON(openai_request), "application/json");
			if(!openai_response||openai_response->status!=200) {
				throw ServerErrorDemand{"OpenAI Request Failed"};
			}
			Json::Value openai_parsed;
			Utils::parseJSON(openai_response->body, &openai_parsed);
			std::string const& order=openai_parsed["choices"][0]["message"]["content"].asString();
			if(order=="REJECT") {
				return {false, "经检测，你的联络不包括有效信息，已被阻止发送。"};
			}else if(order=="HARMFUL") {
				return {false, "经检测，你的联络包含有害内容，已被阻止发送。"};
			}
			fbdb["contacts"].update_one(document{}<<"identifier"<<*identifier<<finalize, document{}<<"$push"<<open_document<<"thread"<<open_document<<"content"<<*content<<"sender"<<*session->user->username<<"time"<<(int64_t)time(nullptr)<<close_document<<close_document<<"$set"<<open_document<<"user_can_add_msg"<<false<<close_document<<finalize);
			goto tg_notify;
			return {true, "OK"};
		}
		if(!anonymous->has_value()||!**anonymous) {
			name=session->user->username;
		}
		fbdb["contacts"].update_one(document{}<<"identifier"<<*identifier<<finalize, document{}<<"$push"<<open_document<<"thread"<<open_document<<"content"<<*content<<"sender"<<name<<"time"<<(int64_t)time(nullptr)<<close_document<<close_document<<"$set"<<open_document<<"user_can_add_msg"<<true<<close_document<<finalize);
		if(closing->has_value()&&**closing) {
			fbdb["contacts"].update_one(document{}<<"identifier"<<*identifier<<finalize, document{}<<"$set"<<open_document<<"closed"<<true<<close_document<<finalize);
		}
		{
			tg_notify:
			std::string tg_notification=fmt::format("*Update on Contact*\n!CONTACTID={}!\nOperator: `{}`\n", *identifier, *session->user->username);
			if(*anonymous&&**anonymous) {
				tg_notification+="*ANONYMOUS MODE*\n";
			}
			if(*closing&&**closing) {
				tg_notification+="*CLOSING*\n";
			}
			tg_notification+="\n\n*Target Contact Thread*\n";
			// Get updated value
			auto spec_contact=*(fbdb["contacts"].find_one(document{}<<"identifier"<<*identifier<<finalize));
			tg_notification+=fmt::format("*Title*: `{}`\n", (std::string)spec_contact["title"].get_string());
			int no=1;
			bsoncxx::array::view thread_db_arr=(bsoncxx::array::view)spec_contact["thread"].get_array();
			for(auto &i:thread_db_arr) {
				tg_notification+=fmt::format("*\\#{}, {}*:\n```\n{}\n```\n", no, i["sender"].get_string(), i["content"].get_string());
				no++;
			}
			std::thread([tg_notification]() {
				httplib::Client tgClient("https://api.telegram.org");
				Json::Value postContent;
				postContent["chat_id"]=Secrets::get_telegram_chat_id();
				postContent["parse_mode"]="MarkdownV2";
				postContent["text"]=tg_notification;
				tgClient.Post(fmt::format("/{}/sendMessage", Secrets::get_telegram_bot_token()), Utils::writeJSON(postContent), "application/json");
			}).detach();
		}
		return {true, "OK"};
	}
	
	LACTION1(DeleteUserContactAction, "delete_user_contact",
			int64_t, identifier, "identifier") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		if(*session->user->isAdministrator) {
			fbdb["contacts"].delete_one(document{}<<"identifier"<<*identifier<<finalize);
			return {true};
		}
		fbdb["contacts"].delete_one(document{}<<"username"<<*session->user->username<<"identifier"<<*identifier<<finalize);
		return {true};
	}
	
	LACTION0(GetIsRateLimitedAction, "get_is_rate_limited") {
		return {true, "", "value", *session->user->rate_limit_counter>=RATE_LIMIT_VALUE};
	}
	
	LACTION1(WaiveRateLimitAction, "waive_rate_limit",
			std::string, captcha, "captcha") {
		if(!session->verifyCaptcha(captcha)) {
			return {false, "验证码不正确"};
		}
		*session->user->rate_limit_counter=0;
		return {true, "ok"};
	}
	
	LACTION7(GetWhitelistAction, "get_whitelist",
			std::optional<std::string>, username, "username",
			std::optional<std::string>, _wquery, "whitelist_query",
			std::optional<uint32_t>, _wpage, "whitelist_page",
			std::optional<std::string>, pquery_username, "p_username",
			std::optional<std::string>, pquery_helper, "p_hname",
			std::optional<std::string>, pquery_description, "p_desc",
			std::optional<uint32_t>, _ppage, "payment_log_page") {
		if(username->has_value()) {
			auto client=mongodb_pool.acquire();
			auto user=(*client)["fastbuilder"]["whitelist"].find_one(document{}<<"username"<<**username<<finalize);
			std::string user_json_str=bsoncxx::to_json(*user);
			if(!user.has_value()) {
				throw DirectReturnDemand{"{}", "application/json"};
			}
			throw DirectReturnDemand{user_json_str, "application/json"};
		}
		if((*_wquery)->size()<4) {
			throw InvalidRequestDemand{"Invalid item `wquery`."};
		}
		std::string const& wquery=**_wquery;
		auto query=document{};
		if(wquery[0]=='1') {
			query<<"admin"<<true;
		}
		if(wquery[1]=='1') {
			query<<"allowed_to_use_phoenix"<<true;
		}
		if(wquery[2]=='1') {
			query<<"banned"<<true;
		}
		if(wquery[3]=='1') {
			query<<"promocodeCount"<<open_document<<"$ne"<<(int32_t)0<<"$exists"<<true<<close_document;
		}
		if(wquery.size()>4) {
			query<<"username"<<open_document<<"$regex"<<bsoncxx::types::b_regex{wquery.substr(4)}<<close_document;
		}
		unsigned int wpage=_wpage->has_value()?**_wpage-1:0;
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		mongocxx::options::find wlist_fo=mongocxx::options::find{}.skip(20*wpage).limit(20);
		auto wlist_o=fbdb["whitelist"].find(query<<finalize, wlist_fo);
		Json::Value wlist_jv(Json::ValueType::arrayValue);
		for(auto &i:wlist_o) {
			std::string i_str=bsoncxx::to_json(i);
			Json::Value item_jv;
			Utils::parseJSON(i_str, &item_jv);
			wlist_jv.append(item_jv);
		}
		auto plistquery=document{};
		if(pquery_username->has_value()) {
			plistquery<<"username"<<open_document<<"$regex"<<bsoncxx::types::b_regex{**pquery_username}<<close_document;
		}
		if(pquery_helper->has_value()) {
			plistquery<<"helper"<<open_document<<"$regex"<<bsoncxx::types::b_regex{**pquery_helper}<<close_document;
		}
		if(pquery_description->has_value()) {
			plistquery<<"description"<<open_document<<"$regex"<<bsoncxx::types::b_regex{**pquery_description}<<close_document;
		}
		unsigned int ppage=_ppage->has_value()?**_ppage-1:0;
		auto plist_fo=mongocxx::options::find{}.sort(document{}<<"_id"<<-1<<finalize).skip(20*ppage).limit(20);
		auto payments_o=fbdb["payments"].find(plistquery<<finalize, plist_fo);
		Json::Value plist_jv(Json::ValueType::arrayValue);
		for(auto &i:payments_o) {
			std::string i_str=bsoncxx::to_json(i);
			Json::Value item_jv;
			Utils::parseJSON(i_str, &item_jv);
			uint64_t date_v=item_jv["date"]["$date"].asUInt64();
			item_jv["date"]=date_v;
			plist_jv.append(item_jv);
		}
		unsigned int pn_wlist=(unsigned int)(fbdb["whitelist"].estimated_document_count()/20.0);
		if(fbdb["whitelist"].estimated_document_count()/20.0>pn_wlist)pn_wlist++;
		unsigned int pn_plist=(unsigned int)(fbdb["payments"].estimated_document_count()/20.0);
		if(fbdb["payments"].estimated_document_count()/20.0>pn_plist)pn_plist++;
		return {true, "ok", "wlist", wlist_jv, "payments", plist_jv, "pn_wlist", pn_wlist, "pn_plist", pn_plist};
	}
	
	LACTION2(UCAddBalanceAction, "add_balance",
			FBWhitelist::User, user, "username",
			uint64_t, count, "value") {
		user->promocode_count+=count;
		return {true, "ok"};
	}
	
	LACTION0(ClearBalanceAction, "clear_balance") {
		session->user->promocode_count.unset();
		return {true, "ok"};
	}
	
	LACTION1(UCDropUserAction, "drop_user",
			FBWhitelist::User, target, "username") {
		FBWhitelist::Whitelist::dropUser(target->username);
		return {true, "Well done"};
	}
	
	LACTION2(UCPublishAnnouncementAction, "publish_announcement",
			std::string, title, "title",
			std::string, content, "content") {
		time_t m_time=time(nullptr);
		struct tm *ptr_time=gmtime(&m_time);
		time_t utc_time=mktime(ptr_time);
		time_t cn_time=utc_time+3600*8;
		std::string cn_time_str(ctime(&cn_time));
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		fbdb["announcements"].insert_one(document{}<<"title"<<*title<<"content"<<*content<<"date"<<cn_time_str<<"author"<<*session->user->username<<"uniqueId"<<Utils::generateUUID()<<finalize);
		return {true};
	}
	
	LACTION1(UCRemoveAnnouncementAction, "remove_announcement",
			std::string, uniqueId, "param") {
		auto client=mongodb_pool.acquire();
		auto fbdb=(*client)["fastbuilder"];
		fbdb["announcements"].delete_one(document{}<<"uniqueId"<<*uniqueId<<finalize);
		return {true};
	}
	
	LACTION2(UpdateUserPasswordAction, "update_user_password",
			FBWhitelist::User, user, "username",
			std::string, new_password, "new_password") {
		if(new_password->length()!=64||new_password=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
			throw InvalidRequestDemand{"Invalid password value"};
		}
		user->password=Utils::sha256(Secrets::addSalt(*new_password));
		return {true};
	}
	
	LACTION1(ListUserRentalServersAction, "list_user_rental_servers",
			FBWhitelist::User, user, "user") {
		return {true, "", "rentalservers", user->rentalservers.toAdministrativeJSON()};
	}
	
	LACTION3(RentalServerOperationAction, "rental_server_operation",
			FBWhitelist::User, user, "username",
			std::optional<std::string>, slotid, "slotid",
			std::string, operation, "operation") {
		if(operation=="unlock") {
			if(!slotid->has_value()) {
				throw InvalidRequestDemand{"Missing required argument `slotid'."};
			}
			auto slot=user->rentalservers[**slotid];
			if(slot) {
				slot.locked.unset();
			}
		}else if(operation=="remove") {
			if(!slotid->has_value()) {
				throw InvalidRequestDemand{"Missing required argument `slotid'."};
			}
			user->rentalservers.erase_slot(**slotid);
		}else if(operation=="add") {
			user->rentalservers.append_slot();
		}else if(operation=="lock") {
			if(!slotid->has_value()) {
				throw InvalidRequestDemand{"Missing required argument `slotid'."};
			}
			auto slot=user->rentalservers[**slotid];
			if(slot) {
				slot.locked=true;
			}
		}else{
			throw InvalidRequestDemand{"Invalid operation"};
		}
		return {true, "ok"};
	}
	
	LACTION3(AddUserAction, "add_user",
			std::optional<FBWhitelist::User>, user_if_exist, "username",
			std::string, username, "username",
			std::string, password, "password") {
		if(user_if_exist->has_value()) {
			return {false, "Such user is already existed."};
		}
		auto newUser=FBWhitelist::Whitelist::createUser(username, Utils::sha256(Secrets::addSalt(password)));
		if(!newUser.has_value()) {
			return {false, "Failed to create user"};
		}
		Json::Value ret;
		ret["username"]=*username;
		ret["banned"]=false;
		ret["password"]=Utils::sha256(Secrets::addSalt(*password));
		ret["owns"]=Json::Value(Json::ValueType::arrayValue);
		ret["free"]=true;
		return {true,"","userwl",ret};
	}
	
	LACTION0(Kickstart2FAAction, "kickstart_2fa") {
		if(session->user->two_factor_authentication_secret.has_value()) {
			throw InvalidRequestDemand{"User already under 2FA"};
		}
		OTPDataPack *otpdata=new OTPDataPack;
		otpdata->secret[16]=0;
		otp_random_base32(16, otpdata->secret);
		session->tmp_otp=std::shared_ptr<OTPDataPack>(otpdata);
		totp_new(&(otpdata->data), otpdata->secret, hmac_algo_sha1, get_current_time, 6, 30);
		char out[256]={0};
		otpuri_build_uri(&(otpdata->data), "FastBuilder", session->user->username->c_str(), "SHA1", out);
		QRCode qrcode;
		uint8_t qrcodeBytes[qrcode_getBufferSize(4)];
		qrcode_initText(&qrcode, qrcodeBytes, 4, ECC_LOW, out);
		cv::Mat qr_image=cv::Mat::zeros(qrcode.size, qrcode.size, CV_8UC3);
		qr_image=cv::Scalar(255,255,255,255);
		for(uint8_t y=0;y<qrcode.size;y++) {
			for(uint8_t x=0;x<qrcode.size;x++) {
				if(qrcode_getModule(&qrcode, x, y)) {
					cv::Vec3b &s=qr_image.at<cv::Vec3b>(cv::Point(x,y));
					s[0]=0;
					s[1]=0;
					s[2]=0;
				}
			}
		}
		cv::Mat larger_qr_image;
		cv::resize(qr_image, larger_qr_image, cv::Size(250, 250), 0, 0, cv::INTER_AREA);
		std::vector<uint8_t> out_buf;
		cv::imencode(".png", larger_qr_image, out_buf);
		return {true, "ok", "plainkey", std::string(otpdata->secret), "qrcode", fmt::format("data:image/png;base64,{}", Utils::base64Encode(std::string((const char *)&out_buf.front(), out_buf.size())))};
	}
	
	LACTION1(FinishRegistering2FAAction, "finish_registering_2fa",
			std::string, code, "code") {
		if(!session->tmp_otp) {
			throw InvalidRequestDemand{"Invalid request"};
		}
		int val=totp_verify(&session->tmp_otp->data, code->c_str(), time(nullptr), 2);
		if(!val) {
			char wanted[7];
			wanted[6]=0;
			totp_now(&session->tmp_otp->data, wanted);
			session->tmp_otp=nullptr;
			return {false, fmt::format("无效验证码, 预期值: {}", wanted)};
		}
		session->user->two_factor_authentication_secret=std::string(session->tmp_otp->secret);
		session->tmp_otp=nullptr;
		return {true, "ok"};
	}
	
	LACTION1(FinishLogin2FAAction, "finish_login_2fa",
			std::string, code, "code") {
		if(!session->login_2fa) {
			throw InvalidRequestDemand{"Invalid request"};
		}
		int val=totp_verify(&session->tmp_otp->data, code->c_str(), time(nullptr), 2);
		if(!val) {
			return {false, "验证码不正确"};
		}
		session->login_2fa=false;
		session->tmp_otp=nullptr;
		return {true};
	}
	
	LACTION0(Retract2FAAction, "retract_2fa") {
		if(!session->user->two_factor_authentication_secret.has_value()) {
			throw InvalidRequestDemand{"Invalid request"};
		}
		session->user->two_factor_authentication_secret.unset();
		return {true};
	}
	
	ACTION3(RegisterAction, "register",
			std::string, username, "username",
			std::string, password, "password",
			std::string, captcha, "captcha") {
		if(password->length()!=64)
			throw InvalidRequestDemand{"Invalid request"};
		if(captcha->length()!=12||!session->verifyCaptcha(captcha)) {
			return {false, "验证码不正确"};
		}
		std::regex username_req("^[A-Za-z0-9]+$", std::regex_constants::ECMAScript);
		std::smatch matching_buf;
		std::string perm_un=*username;
		if(!std::regex_match(perm_un, matching_buf, username_req)) {
			return {false, "无效用户名"};
		}
		if(password=="2dcc453c31b52d2b1137e0d02e823d64dbf3c722551c545e8889d8e45f54fa32")
			return {false, "无效密码"};
		if(FBWhitelist::Whitelist::findUser(username).has_value())
			return {false, "用户名被占用"};
		std::optional<FBWhitelist::User> user=FBWhitelist::Whitelist::createUser(username, Utils::sha256(Secrets::addSalt(password)));
		if(!user.has_value()) {
			throw ServerErrorDemand{"Unknown exception"};
		}
		*user->keep_reference=true;
		session->user=std::make_shared<FBWhitelist::User>(*user);
		session->login_2fa=false;
		session->token_login=false;
		session->phoenix_only=false;
		SPDLOG_INFO("User Center register: Username: {}, IP: {}", *username, session->ip_address);
		return {true};
	}
	
	ACTION6(PhoenixLoginAction, "phoenix/login",
			std::optional<std::string>, login_token, "login_token",
			std::optional<std::string>, _username, "username",
			std::optional<std::string>, _password, "password",
			std::string, server_code, "server_code",
			std::string, server_passcode, "server_passcode",
			std::string, client_public_key, "client_public_key") {
		if(session->user) {
			throw InvalidRequestDemand{"Already logged in"};
		}
		std::string username;
		std::string password;
		if(!login_token->has_value()) {
			if(!_username->has_value()||!_password->has_value()) {
				throw InvalidRequestDemand{"Insufficient arguments"};
			}
			username=**_username;
			password=Utils::sha256(Secrets::addSalt(**_password));
		}else{
			if(_username->has_value()) {
				throw InvalidRequestDemand{"Conflicted arguments"};
			}
			Json::Value token_content;
			bool parsed=Utils::parseJSON(FBToken::decrypt(**login_token), &token_content, nullptr);
			if(!parsed||!token_content["username"].isString()||!token_content["password"].isString()||!token_content["newToken"].asBool()) {
				return {false, "Invalid token"};
			}
			username=token_content["username"].asString();
			password=token_content["password"].asString();
		}
		std::optional<FBWhitelist::User> pUser=FBWhitelist::Whitelist::findUser(username);
		if(!pUser.has_value()||pUser->password!=password) {
			return {false, "Invalid username or password"};
		}
		auto user=pUser;
		if(user->free&&!user->expiration_date.stillAlive()) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no payment] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "月额 Plan 失效已过或从未激活，请前往用户中心购买。"};
		}
		if(!user->nemc_access_info.has_value()) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [no helper] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "未创建辅助用户，请前往用户中心创建。", "translation", 7};
		}
		bool approved=false;
		if(!user->isAdministrator) {
			if(!approved&&user->rentalservers.size()) {
				for(auto const& ind:user->rentalservers) {
					if(*ind.second.content==*server_code) {
						approved=true;
						break;
					}
				}
			}
			if(!approved&&!user->isCommercial) {
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [unauthorized server code] IP: {}", *user->username, *server_code, session->ip_address);
				return {false, "指定的租赁服号未授权，请前往用户中心设置", "translation", 13};
			}
			(*user->rate_limit_counter)++;
			if(*user->rate_limit_counter>=RATE_LIMIT_VALUE) {
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [RATE LIMIT] IP: {}", *user->username, *server_code, session->ip_address);
				return {false, "[RATE LIMIT] 您的请求过于频繁，现已被限制使用，请稍等一段时间或前往用户中心输入验证码解除限制。"};
			}
		}
		NEMCUser nemcUser;
		if(user->nemc_temp_info.has_value()) {
			nemcUser=user->nemc_temp_info;
		}
		if(!nemcUser.isLoggedIn()) {
			std::variant<NEMCUser, NEMCError> possibleUser=user->nemc_access_info->auth();
			if(std::holds_alternative<NEMCError>(possibleUser)) {
				NEMCError err=std::get<NEMCError>(possibleUser);
				SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
				return {false, err.description, "translation", err.translation>0?err.translation:-1};
			}
			nemcUser=std::get<NEMCUser>(possibleUser);
			user->nemc_temp_info=nemcUser;
		}
		auto _helperun=nemcUser.getUsername();
		if(std::holds_alternative<NEMCError>(_helperun)) {
			NEMCError err=std::get<NEMCError>(_helperun);
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
			return {false, err.description, "translation", err.translation>0?err.translation:-1};
		}
		std::string helperun=std::get<std::string>(_helperun);
		if(helperun.size()==0) {
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [helper no username] IP: {}", *user->username, *server_code, session->ip_address);
			return {false, "辅助用户用户名设置无效，请前往用户中心重新设置", "translation", 9};
		}
		auto impactres=nemcUser.doImpact(server_code, server_passcode, client_public_key, helperun);
		if(std::holds_alternative<NEMCError>(impactres)) {
			NEMCError err=std::get<NEMCError>(impactres);
			if(err.translation==-20) {
				err.description="FINAL STAGE PARSING ERROR";
			}
			SPDLOG_INFO("Phoenix login (rejected): {} -> {} [nemc error: {}] IP: {}", *user->username, *server_code, err.description, session->ip_address);
			return {false, err.description, "translation", err.translation>0?err.translation:-1};
		}
		SPDLOG_INFO("Phoenix login (passed): {} -> {}, Helper: {}, IP: {}", *user->username, *server_code, helperun, session->ip_address);
		std::string usernameForJS=fmt::format("{}|{}", *user->username, Utils::cv4Sign(user->username));
		std::string pubKey;
		if(!user->signing_key.has_value()) {
			auto keyPair=Utils::generateRSAKeyPair();
			FBWhitelist::SigningKeyPair skp;
			skp.private_key=keyPair.first;
			skp.public_key=keyPair.second;
			pubKey=keyPair.second;
			user->signing_key=skp;
		}else{
			pubKey=(std::string)user->signing_key->public_key;
		}
		std::string privateSigningKeyProve=fmt::format("{}|{}", pubKey, *user->username);
		privateSigningKeyProve.append(fmt::format("::{}", Utils::cv4Sign(privateSigningKeyProve)));
		session->user=std::make_shared<FBWhitelist::User>(*pUser);
		session->login_2fa=false;
		session->phoenix_only=true;
		std::string rettoken="";
		if(!login_token->has_value()) {
			Json::Value token;
			token["username"]=username;
			token["password"]=password;
			token["newToken"]=true;
			rettoken=FBToken::encrypt(token);
		}
		std::string respond_to;
		if(user->cn_username.has_value()) {
			respond_to=user->cn_username;
		}
		std::pair<std::string, std::string> chainInfo=std::get<std::pair<std::string, std::string>>(impactres);
		return {true, "well done", "chainInfo", chainInfo.first, "ip_address", chainInfo.second, "uid", nemcUser.getUID(), "username", helperun, "privateSigningKey", user->signing_key->private_key, "prove", privateSigningKeyProve, "token", rettoken, "respond_to", respond_to};
	}
	
	LACTION1(PhoenixTransferStartTypeAction, "phoenix/transfer_start_type",
			std::string, content, "content") {
		if(!session->user->nemc_temp_info.has_value()) {
			throw ServerErrorDemand{"No login found"};
		}
		return {true, "", "data", NEMCCalculateStartType(content, session->user->nemc_temp_info->getUID())};
	}
	
	LACTION1(PhoenixTransferChecknumAction, "phoenix/transfer_check_num",
			std::string, data, "data") {
		auto v=get_check_num(data);
		if(!v.length()) {
			return {false, "Failed"};
		}
		return {true, "Perfect", "value", v};
	}
	
	LACTION1(HelperChargeAction, "helper_charge",
			uint32_t, value, "value") {
		if(*value>=800||*value<6)
			throw InvalidRequestDemand{"Invalid amount given"};
		std::string return_url=fmt::format("https://api.fastbuilder.pro/api/stripe_recover?is_checkout=1&ssid={}", session->session_id);
		if(getenv("DEBUG")) {
			return_url=fmt::format("http://127.0.0.1:8687/api/stripe_recover?is_checkout=1&ssid={}", session->session_id);
		}
		httplib::Params params{
			{"line_items[0][quantity]", "1"},
			{"line_items[0][price_data][currency]", "cny"},
			{"line_items[0][price_data][product_data][name]", "FBUC Charge"},
			{"line_items[0][price_data][unit_amount]", std::to_string(value*100)},
			{"mode", "payment"},
			{"allow_promotion_codes", "true"},
			{"payment_method_types[0]", "card"},
			{"payment_method_types[1]", "alipay"},
			{"success_url", return_url},
			{"cancel_url", return_url}
		};
		auto stripe_res=stripeClient.Post("/v1/checkout/sessions", params);
		if(!stripe_res) {
			throw ServerErrorDemand{"Unknown error"};
		}
		Json::Value stripe_parsed;
		if(!Utils::parseJSON(stripe_res->body, &stripe_parsed, nullptr)) {
			throw ServerErrorDemand{"Failed to parse stripe response"};
		}
		PaymentIntent *chargeIntent=new PaymentIntent;
		chargeIntent->session=session;
		chargeIntent->price=801;
		chargeIntent->stripe_price=801;
		chargeIntent->helper_price=value;
		chargeIntent->card_only=true;
		auto shared_intent=std::shared_ptr<PaymentIntent>(chargeIntent);
		payments_mutex.lock();
		payment_intents[stripe_parsed["id"].asString()]=shared_intent;
		payments_mutex.unlock();
		session->payment_intent=shared_intent;
		return {true, "created", "url", stripe_parsed["url"]};
	}
	
	LACTION0(GetPhoenixTokenAction, "get_phoenix_token") {
		DirectReturnDemand d;
		d.type="text/plain";
		Json::Value token;
		token["username"]=session->user->username;
		token["password"]=session->user->password;
		token["newToken"]=true;
		d.content=FBToken::encrypt(token);
		d.disposition="attachment;filename=fbtoken";
		throw d;
	}
	
	LACTION0(ExportUserDataAction, "export_user_data") {
		throw ServerErrorDemand{"Not implemented yet"};
	}
	
	static FBUCActionCluster ucGeneralActions(0, {
		Action::enmap(new APIListAction),
		Action::enmap(new LoginAction),
		Action::enmap(new UCCaptchaAction),
		Action::enmap(new FetchAnnouncementsAction),
		Action::enmap(new UCLogoutAction),
		Action::enmap(new FetchProfileAction),
		Action::enmap(new UCGetHelperStatusAction),
		Action::enmap(new SaveClientUsernameAction),
		Action::enmap(new SaveSlotAction),
		Action::enmap(new UCHelperOperationAction),
		Action::enmap(new UCGetProductListAction),
		Action::enmap(new AddProductToCartAction),
		Action::enmap(new GetShoppingCartAction),
		Action::enmap(new EraseFromShoppingCartAction),
		Action::enmap(new GenerateBillAction),
		Action::enmap(new GetBillAction),
		Action::enmap(new CheckPaymentAction),
		Action::enmap(new UCGetBalanceAction),
		Action::enmap(new PairPaymentAction),
		Action::enmap(new ApprovePaymentAction),
		Action::enmap(new ChangePasswordAction),
		//Action::enmap(new UCCalculateMonthlyPlanDurationAction),
		Action::enmap(new RedeemForFreeAction),
		Action::enmap(new UCVoteAnnouncementAction),
		Action::enmap(new GetThemeInfoAction),
		Action::enmap(new ApplyThemeAction),
		Action::enmap(new StripeCreateSessionAction),
		Action::enmap(new GetPaymentLogAction),
		Action::enmap(new GetUserContactsAction),
		Action::enmap(new CreateUserContactAction),
		Action::enmap(new UpdateUserContactAction),
		Action::enmap(new DeleteUserContactAction),
		//Action::enmap(new GetIsRateLimitedAction),
		Action::enmap(new WaiveRateLimitAction),
		Action::enmap(new Kickstart2FAAction),
		Action::enmap(new FinishRegistering2FAAction),
		Action::enmap(new FinishLogin2FAAction),
		Action::enmap(new Retract2FAAction),
		Action::enmap(new RegisterAction),
		Action::enmap(new PhoenixLoginAction),
		Action::enmap(new PhoenixTransferStartTypeAction),
		Action::enmap(new PhoenixTransferChecknumAction),
		Action::enmap(new HelperChargeAction),
		Action::enmap(new GetPhoenixTokenAction)
	});
	
	static FBUCActionCluster ucAdministrativeActions(1, {
		Action::enmap(new GetWhitelistAction),
		Action::enmap(new UCAddBalanceAction),
		Action::enmap(new ClearBalanceAction),
		Action::enmap(new UCDropUserAction),
		Action::enmap(new UCPublishAnnouncementAction),
		Action::enmap(new UCRemoveAnnouncementAction),
		Action::enmap(new UpdateUserPasswordAction),
		Action::enmap(new ListUserRentalServersAction),
		Action::enmap(new RentalServerOperationAction),
		Action::enmap(new AddUserAction)
	});
	
	static void enter_action_clust(FBUC::Action *action, Json::Value& parsed_args, const httplib::Request& req, httplib::Response& res, bool administrative=false);
}

static void FBUC::enter_action_clust(FBUC::Action *action, Json::Value& parsed_args, const httplib::Request& req, httplib::Response& res, bool administrative) {
	std::string sessionId="";
	if(req.has_header("Authorization")) {
		std::string sessionId_cookie=req.get_header_value("Authorization");
		std::regex sessionId_regex("^Bearer (.*?)$", std::regex_constants::ECMAScript);
		std::smatch sessionId_match;
		if(std::regex_match(sessionId_cookie, sessionId_match, sessionId_regex)) {
			userlist_mutex.lock_shared();
			if(userlist.contains(sessionId_match[1].str())) {
				sessionId=sessionId_match[1].str();
			}
			userlist_mutex.unlock_shared();
		}
	}else if(req.has_param("secret")) {
		std::string const& secret_val=req.get_param_value("secret");
		userlist_mutex.lock_shared();
		if(userlist.contains(secret_val)) {
			sessionId=secret_val;
		}
		userlist_mutex.unlock_shared();
	}
	parsed_args["secret"]=sessionId;
	auto maybeSession=userlist.find(sessionId);
	try {
		if(!sessionId.length()) {
			//res.set_content("401 Unauthorized\n\n", "text/plain");
			//res.status=401;
			throw FBUC::UnauthorizedDemand{"Unauthorized"};
			return;
		}
		FBUC::Session currentSession=maybeSession->second;
		std::lock_guard<std::mutex> the_lock(currentSession->op_lock);
		if(!currentSession->user&&(administrative||action->mandatory_login())) {
			throw FBUC::InvalidRequestDemand{"Login Required"};
		}
		if(currentSession->user&&currentSession->login_2fa) {
			if(action->action_name!="api"&&
				action->action_name!="fetch_announcements"&&
				action->action_name!="finish_login_2fa"&&
				action->action_name!="logout") {
				throw FBUC::AccessDeniedDemand{"Please complete 2FA"};
			}
		}
		if(currentSession->user&&currentSession->phoenix_only) {
			std::regex phoenix_only_match("^phoenix\\/(.*?)$", std::regex_constants::ECMAScript);
			std::smatch sm;
			if(!std::regex_match(action->action_name, sm, phoenix_only_match)&&action->action_name!="api"&&action->action_name!="logout") {
				throw FBUC::AccessDeniedDemand{"Restricted to phoenix/"};
			}
		}
		if(administrative&&(!currentSession->user||!*currentSession->user->isAdministrator)) {
			throw FBUC::AccessDeniedDemand{"Access Denied"};
		}
		currentSession->last_alive=time(nullptr);
		Json::Value ret=action->_execute(parsed_args, currentSession);
		if(ret["code"].isInt()&&ret["code"].asInt()==-400) {
			throw FBUC::InvalidRequestDemand{ret["message"].asString()};
		}
		ret.removeMember("code");
		res.set_content(Utils::writeJSON(ret), "application/json");
		return;
	}catch(const FBUC::RedirectDemand& rdr) {
		res.status=302;
		res.set_header("Location", rdr.target);
	}catch(const FBUC::ErrorDemand& ird) {
		res.status=ird.status();
		res.set_content(ird.print_with_stack_dump(), "text/plain");
	}catch(const FBUC::DirectReturnDemand& drd) {
		if(drd.disposition.length()) {
			res.set_header("Content-Disposition", drd.disposition);
		}
		res.set_content(drd.content, drd.type);
	}
}


extern "C" void init_user_center() {
	stripeClient.set_keep_alive(true);
	stripeClient.set_bearer_token_auth(Secrets::get_stripe_key());
	openaiClient.set_keep_alive(true);
	openaiClient.set_bearer_token_auth(Secrets::get_openai_token());
	std::thread([](){
		while(1) {
			sleep(120);
			userlist_mutex.lock();
			time_t now=time(nullptr);
			for(auto it=userlist.begin();it!=userlist.end();) {
				std::shared_ptr<FBUC::UserSession> session=it->second;
				if(!session) {
					SPDLOG_ERROR("Empty UserSession ptr present! Check your code!");
					it=userlist.erase(it);
					continue;
				}
				time_t time_passed=now-session->last_alive;
				if(time_passed>3600) {
					if(it->second->user) {
						*it->second->user->keep_reference=false;
					}
					it=userlist.erase(it);
					continue;
				}
				if(!it->second->user&&time_passed>300) {
					it=userlist.erase(it);
					continue;
				}
				++it;
			}
			userlist_mutex.unlock();
			payments_mutex.lock();
			for(auto it=payment_intents.begin();it!=payment_intents.end();) {
				std::shared_ptr<FBUC::PaymentIntent> intent=it->second;
				if(!intent) {
					SPDLOG_ERROR("Empty PaymentIntent ptr present! Check your code!");
					it=payment_intents.erase(it);
					continue;
				}
				if(intent->session.expired()) {
					it=payment_intents.erase(it);
					continue;
				}else if(intent->approved) {
					intent->session.lock()->payment_intent=nullptr;
					it=payment_intents.erase(it);
					continue;
				}
				++it;
			}
			payments_mutex.unlock();
		}
	}).detach();
	std::thread([](){
		httplib::Server server;
		server.Get("/", [](const httplib::Request& req, httplib::Response& res) {
			res.set_content("Hello, world!", "text/plain");
		});
		server.Get("/api/stripe_recover", [](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_param("ssid")) {
				res.status=400;
				res.set_content("400 Illegal Request", "text/plain");
				return;
			}
			res.status=302;
			std::string mukaisaki=req.has_param("is_checkout")?"/cashier":"/pay";
			if(getenv("DEBUG")) {
				res.set_header("Location", fmt::format("http://127.0.0.1/fbuc/bin/#!/router/enter?to={}&secret={}",mukaisaki,req.get_param_value("ssid")));
				return;
			}
			res.set_header("Location", fmt::format("https://user.fastbuilder.pro/#!/router/enter?to={}&secret={}",mukaisaki,req.get_param_value("ssid")));
		});
		server.Options("/api/new", [](const httplib::Request& req, httplib::Response& res) {
			res.status=204;
		});
		server.Get("/api/new", [](const httplib::Request& req, httplib::Response& res) {
			std::string sessionId;
			userlist_mutex.lock();
			while(true) {
				sessionId=Utils::generateUUID();
				if(!userlist.contains(sessionId)) {
					//res.set_header("Set-Cookie", fmt::format("ssid={}", sessionId));
					auto new_ptr=std::make_shared<FBUC::UserSession>();
					new_ptr->session_id=sessionId;
					new_ptr->last_alive=time(nullptr);
					std::string ip_address="127.0.0.1";
					if(req.has_header("X-Forwarded-For")) {
						std::string const& ip_v=req.get_header_value("X-Forwarded-For");
						std::string::size_type n=ip_v.find(',');
						if(n==std::string::npos) {
							ip_address=ip_v;
						}else{
							ip_address=ip_v.substr(0, n);
						}
					}
					new_ptr->ip_address=std::move(ip_address);
					userlist[sessionId]=new_ptr;
					break;
				}
			}
			userlist_mutex.unlock();
			res.set_content(sessionId, "text/plain");
		});
		server.Get("/remote_auth", [&](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_header("X-Auth-HttpRequest-Query")) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			std::string query_val=req.get_header_value("X-Auth-HttpRequest-Query");
			std::regex secret_regex("(^|&)secret=(.*?)(&|$)", std::regex_constants::ECMAScript);
			std::smatch secret_match;
			if(!std::regex_search(query_val, secret_match, secret_regex)) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			std::string const& secret_val=secret_match[2].str();
			if(!userlist.contains(secret_val)) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			std::shared_ptr<FBUC::UserSession> session=userlist[secret_val];
			if(!session->user||(req.has_param("admin")&&!*session->user->isAdministrator)) {
				res.status=403;
				res.set_content("403 Please Reject", "text/plain");
				return;
			}
			res.set_header("Auth-User", session->user->username);
		});
		server.Post("/api/telegram/webhook", [&](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_header("X-Telegram-Bot-Api-Secret-Token")&&req.get_header_value("X-Telegram-Bot-Api-Secret-Token")!=Secrets::get_telegram_webhook_secret()) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			Json::Value parsed_req;
			Utils::parseJSON(req.body, &parsed_req);
			if(parsed_req["message"].isMember("reply_to_message")) {
				std::string reply_text=parsed_req["message"]["text"].asString();
				if(memcmp(reply_text.c_str(), "/reply\n", 7)==0) {
					std::string original=parsed_req["message"]["reply_to_message"]["text"].asString();
					std::regex contact_id_regex("!CONTACTID=(\\d+)!", std::regex_constants::ECMAScript);
					std::smatch contact_id_match;
					if(!std::regex_search(original, contact_id_match, contact_id_regex)) {
						return;
					}
					std::string contact_id_str=contact_id_match[1].str();
					
				}
			}
		});
		server.Post("/api/stripe/webhook", [&](const httplib::Request& req, httplib::Response& res) {
			if(!req.has_header("Stripe-Signature")) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			time_t current_time=time(nullptr);
			std::string signature_content=req.get_header_value("Stripe-Signature");
			std::regex t_regex("t=([0-9]+)(,|$)", std::regex_constants::ECMAScript);
			std::regex v1_regex("v1=([a-z0-9]{64})(,|$)", std::regex_constants::ECMAScript);
			std::smatch t_match;
			std::smatch v1_match;
			if(!std::regex_search(signature_content, t_match, t_regex)||!std::regex_search(signature_content, v1_match, v1_regex)) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			time_t given_time=std::stol(t_match[1].str());
			if(current_time-given_time>120) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			std::string signed_payload=fmt::format("{}.{}", t_match[1].str(), req.body);
			std::string key=Secrets::get_stripe_webhook_secret();
			std::string out_md;
			out_md.resize(32);
			unsigned int out_md_len=32;
			HMAC(EVP_sha256(), key.c_str(), key.length(), (const unsigned char *)signed_payload.c_str(), signed_payload.size(), (unsigned char *)&out_md.front(), &out_md_len);
			std::string expected_signature=Utils::str2hex(out_md);
			if(expected_signature!=v1_match[1].str()) {
				res.status=400;
				res.set_content("Illegal request", "text/plain");
				return;
			}
			Json::Value event;
			Utils::parseJSON(req.body, &event, nullptr);
			std::string event_type=event["type"].asString();
			if(event_type!="checkout.session.completed"&&event_type!="charge.succeeded"&&event_type!="payment_intent.succeeded") {
				res.set_content("200 but not expected", "text/plain");
				return;
			}
			Json::Value &session=event["data"]["object"];
			if(event_type=="charge.succeeded") {
				return;
			}
			payments_mutex.lock_shared();
			if(!payment_intents.contains(session["id"].asString())) {
				payments_mutex.unlock_shared();
				return;
			}
			auto intent=payment_intents[session["id"].asString()];
			payments_mutex.unlock_shared();
			std::shared_ptr<FBUC::UserSession> user=intent->session.lock();
			if(!user) {
				// ???
				res.status=500;
				return;
			}
			if(intent->content.size()==0) {
				user->user->promocode_count+=intent->helper_price;
				return;
			}
			FBUC::finalizePaymentIntent(intent, user->user.get(), fmt::format("@Stripe+{}", session["id"].asString()));
		});
		for(auto const& i:fbuc_actions) {
			server.Options(fmt::format("/api/{}",i.second->action_name), [&](const httplib::Request& req, httplib::Response& res) {
				res.status=204;
			});
			server.Get(fmt::format("/api/{}",i.second->action_name), [&](const httplib::Request& req, httplib::Response& res) {
				Json::Value parsed_args;
				for(const auto &i:req.params) {
					parsed_args[i.first]=i.second;
				}
				enter_action_clust(i.second, parsed_args, req, res);
			});
			server.Post(fmt::format("/api/{}",i.second->action_name), [&](const httplib::Request& req, httplib::Response& res) {
				Json::Value parsed_args;
				std::string error_message;
				bool isSucc=Utils::parseJSON(req.body, &parsed_args, &error_message);
				if(!isSucc) {
					res.status=400;
					res.set_content(fmt::format("400 Invalid Request\n\nExpected JSON data, where JSON parsing failed.\n\nError: {}", error_message), "text/plain");
					return;
				}
				enter_action_clust(i.second, parsed_args, req, res);
			});
		}
		for(auto const& i:fbuc_administrative_actions) {
			server.Options(fmt::format("/api/administrative/{}",i.second->action_name), [&](const httplib::Request& req, httplib::Response& res) {
				res.status=204;
			});
			server.Get(fmt::format("/api/administrative/{}",i.second->action_name), [&](const httplib::Request& req, httplib::Response& res) {
				Json::Value parsed_args;
				for(const auto &i:req.params) {
					parsed_args[i.first]=i.second;
				}
				enter_action_clust(i.second, parsed_args, req, res, true);
			});
			server.Post(fmt::format("/api/administrative/{}",i.second->action_name), [&](const httplib::Request& req, httplib::Response& res) {
				Json::Value parsed_args;
				std::string error_message;
				bool isSucc=Utils::parseJSON(req.body, &parsed_args, &error_message);
				if(!isSucc) {
					res.status=400;
					res.set_content(fmt::format("400 Invalid Request\n\nExpected JSON data, where JSON parsing failed.\n\nError: {}", error_message), "text/plain");
					return;
				}
				enter_action_clust(i.second, parsed_args, req, res, true);
			});
		}
		server.set_post_routing_handler([](const auto& req, auto& res) {
			res.set_header("access-control-allow-credentials", "true");
			res.set_header("access-control-allow-headers", "Origin, Authorization, Accept, Content-Type, Cookie");
			res.set_header("access-control-allow-methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS");
			if(req.has_header("Origin")&&req.get_header_value("Origin")=="http://127.0.0.1") {
				res.set_header("access-control-allow-origin", "http://127.0.0.1");
			}else{
				res.set_header("access-control-allow-origin", "https://user.fastbuilder.pro");
			}
		});
		server.listen("127.0.0.1", 8687);
	}).detach();
}
