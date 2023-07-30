#pragma once
#define WHITELIST_PRIVATE_INCLUDED
#include <unordered_map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <json/json.h>
#include <fmt/format.h>
#include <mongocxx/client.hpp>
#include "nemc_helper.h"

#include <bsoncxx/builder/stream/document.hpp>

namespace FBWhitelist {
	
	class Whitelist;
	
	template<typename T, typename DT=T>
	class RentalServerDBValue;
	
	template<typename T, typename DT=T>
	class DBValue {
	protected:
		std::shared_ptr<std::mutex> w_lock=std::make_shared<std::mutex>();
		std::shared_ptr<std::shared_ptr<T>> object;
		std::shared_ptr<std::string> identifier;
		const char *item_name;
		
		void _set(T const& target);
		DBValue(const char *_in) : item_name(_in) {};
		DBValue(const char *item_name, std::shared_ptr<std::string> identifier, T const& item);
		DBValue(const char *item_name, std::shared_ptr<std::string> identifier);
		DBValue(const char *item_name, std::shared_ptr<std::string> identifier, bsoncxx::document::view db_view);
		
		DBValue() {}
		virtual void load(std::shared_ptr<std::string> identifier, bsoncxx::document::view db_view);
	public:
		virtual void set(T const& target);
		virtual void unset();
		virtual DBValue& operator=(T const& target);
		virtual DBValue& operator+=(T const& target);
		virtual DBValue& operator-=(T const& target);
		virtual bool operator==(T const& target) const;
		virtual std::strong_ordering operator<=>(T const& target) const;
		virtual operator T() const;
		virtual operator Json::Value() const;
		virtual T operator*() const;
		virtual T const* operator->() const;
		virtual inline bool has_value() const { return (bool)*object; }
		virtual bool stillAlive() const;
		
		friend class User;
		friend class Whitelist;
		friend class RentalServerStore;
	};
	
	template<typename T, typename DT>
	class RentalServerDBValue : public FBWhitelist::DBValue<T, DT> {
	private:
		std::string slotid;
	protected:
		RentalServerDBValue(const char *item_name, std::shared_ptr<std::string> identifier, std::string slotid, T const& item) : DBValue<T, DT>(item_name, identifier, item), slotid(slotid) {}
		RentalServerDBValue(const char *item_name, std::shared_ptr<std::string> identifier, std::string slotid) : DBValue<T, DT>(item_name, identifier), slotid(slotid) {}
		RentalServerDBValue(const char *item_name, std::shared_ptr<std::string> identifier, std::string slotid, bsoncxx::array::element const& db_view) : DBValue<T, DT>(item_name, identifier, db_view.get_document()), slotid(slotid) {}
		
		RentalServerDBValue() {}
	public:
		virtual void set(T const& target);
		virtual void unset();
		virtual RentalServerDBValue& operator=(T const& target);
		virtual RentalServerDBValue& operator+=(T const& target);
		virtual RentalServerDBValue& operator-=(T const& target);
		virtual bool operator==(T const& target) const;
		virtual std::strong_ordering operator<=>(T const& target) const;
		virtual operator T() const;
		virtual operator Json::Value() const;
		virtual T operator*() const;
		virtual T const* operator->() const;
		virtual bool has_value() const;
		
		friend class RentalServerStore;
		friend class RentalServerItem;
		friend class Whitelist;
	};
	
	struct RentalServerItem {
	private:
		bool is_valid;
	public:
		RentalServerDBValue<std::string> content="content";
		RentalServerDBValue<std::string> slotid="slotid";
		RentalServerDBValue<uint64_t, int64_t> lastdate="lastdate";
		RentalServerDBValue<bool> locked="locked";
		
		operator bool() const;
		friend class RentalServerStore;
		friend class Whitelist;
	};
	
	class RentalServerStore {
		static RentalServerItem InvalidRentalServer;
	
		std::shared_ptr<std::string> username;
		std::shared_ptr<std::mutex> write_mutex=std::make_shared<std::mutex>();
		std::shared_ptr<std::unordered_map<std::string, RentalServerItem>> rentalServerMap=std::make_shared<std::unordered_map<std::string, RentalServerItem>>();
	
		RentalServerStore()=default;
	public:
		std::unordered_map<std::string, RentalServerItem>::const_iterator begin() const;
		std::unordered_map<std::string, RentalServerItem>::const_iterator end() const;
		size_t size() const;
		
		void erase_slot(std::unordered_map<std::string, RentalServerItem>::iterator &item_iter);
		void erase_slot(std::string const& key);
		RentalServerItem& append_slot();
		RentalServerItem& operator[](std::string const& key);
		RentalServerItem& at(std::string const& key);
		Json::Value toDescriptiveJSON() const;
		Json::Value toAdministrativeJSON() const;
		
		friend class User;
		friend class Whitelist;
	};
	
	struct SigningKeyPair {
		bsoncxx::document::value stored_doc_value = bsoncxx::builder::stream::document{}<<bsoncxx::builder::stream::finalize;
	
		std::string private_key;
		std::string public_key;
	
		SigningKeyPair()=default;
		SigningKeyPair(bsoncxx::document::element const& db_item);
		operator bsoncxx::document::view();
		bool operator==(FBWhitelist::SigningKeyPair const& value) const;
	};
	
	struct User {
		std::string user_oid;
		RentalServerStore rentalservers;
		DBValue<std::string> username="username";
		DBValue<std::string> cn_username="cn";
		//DBValue<bool> banned;
		//DBValue<std::string> ban_reason;
		DBValue<std::string> password="password";
		DBValue<bool> transferred="transferred";
		DBValue<bool> isAdministrator="admin";
		DBValue<bool> isCommercial="allowed_to_use_phoenix";
		DBValue<NEMCUserAuthInfo> nemc_access_info="nemc_access_info";
		DBValue<NEMCUser> nemc_temp_info="nemc_temp_info";
		DBValue<SigningKeyPair> signing_key="signingKey";
		DBValue<int64_t, int32_t> promocode_count="promocodeCount";
		DBValue<std::string> preferredtheme="preferredtheme";
		DBValue<bool> free="free";
		DBValue<uint64_t, int64_t> expiration_date="expiration_date";
		DBValue<uint64_t, int64_t> next_drop_date="next_drop_date";
		DBValue<bool> banned_from_payment="banned_from_payment";
		DBValue<std::string> payment_verify_fingerprint="payment_verify_fingerprint";
		DBValue<int32_t> points="points";
		DBValue<std::string> two_factor_authentication_secret="two_factor_authentication_secret";
		std::shared_ptr<uint32_t> rate_limit_counter=std::make_shared<uint32_t>(0);
		std::shared_ptr<bool> keep_reference=std::make_shared<bool>(false);
	};

	class Whitelist {
	private:
		static std::unordered_map<std::string, std::shared_ptr<FBWhitelist::User>> stored_user_map;
		static std::mutex user_finding_lock;
		static std::shared_mutex user_pool_lock;
		static unsigned short op_count_to_clearance;
		
		static std::shared_ptr<FBWhitelist::User> _findUser(std::string const& username);
	public:
		static std::shared_ptr<FBWhitelist::User> acquireUser(std::string const& username);
		static std::optional<FBWhitelist::User> findUser(std::string const& username);
		static std::optional<FBWhitelist::User> createUser(std::string const& username, std::string const& password);
		
		static void dropUser(std::string const& username);
		static void emptyCache();
	};

};

