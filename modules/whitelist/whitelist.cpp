#include "whitelist.h"

#include <mongocxx/instance.hpp>
#include <mongocxx/client.hpp>
#include <mongocxx/pool.hpp>
#include <mongocxx/uri.hpp>
#include <bsoncxx/json.hpp>
#include <bsoncxx/builder/stream/helpers.hpp>
#include <bsoncxx/builder/stream/document.hpp>
#include <bsoncxx/builder/stream/array.hpp>
#include <fmt/format.h>
#include <spdlog/spdlog.h>
#include <type_traits>

#include "utils.h"

using bsoncxx::builder::stream::close_array;
using bsoncxx::builder::stream::close_document;
using bsoncxx::builder::stream::document;
using bsoncxx::builder::stream::finalize;
using bsoncxx::builder::stream::open_array;
using bsoncxx::builder::stream::open_document;

extern mongocxx::pool mongodb_pool;


template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>::DBValue(const char *item_name, std::shared_ptr<std::string> username, T const& item) {
	this->item_name=item_name;
	this->identifier=username;
	std::shared_ptr<T> *inner=new std::shared_ptr<T>(new T(item));
	std::shared_ptr<std::shared_ptr<T>> outer=std::shared_ptr<std::shared_ptr<T>>(inner);
	object=outer;
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>::DBValue(const char *item_name, std::shared_ptr<std::string> username) {
	this->item_name=item_name;
	this->identifier=username;
	std::shared_ptr<T> *inner=new std::shared_ptr<T>();
	std::shared_ptr<std::shared_ptr<T>> outer=std::shared_ptr<std::shared_ptr<T>>(inner);
	object=outer;
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>::DBValue(const char *item_name, std::shared_ptr<std::string> username, bsoncxx::document::view db_view) {
	this->item_name=item_name;
	this->identifier=username;
	std::shared_ptr<T> *inner=nullptr;
	if(db_view[item_name]) {
		if constexpr(std::is_same<DT, std::string>::value) {
			inner=new std::shared_ptr<T>(new T((T)(std::string)db_view[item_name].get_string()));
		}else if constexpr(std::is_same<DT, bool>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name].get_bool()));
		}else if constexpr(std::is_same<DT, int32_t>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name].get_int32()));
		}else if constexpr(std::is_same<DT, int64_t>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name].get_int64()));
		}else {
			SPDLOG_CRITICAL("Unknown type for DBValue runtime construction");
			throw std::runtime_error("Unexpected type for FBWhitelist::DBValue<T, DT>::DBValue");
		}
	}
	if(!inner)
		inner=new std::shared_ptr<T>();
	std::shared_ptr<std::shared_ptr<T>> outer=std::shared_ptr<std::shared_ptr<T>>(inner);
	object=outer;
}

template <typename T, typename DT>
void FBWhitelist::DBValue<T, DT>::load(std::shared_ptr<std::string> username, bsoncxx::document::view db_view) {
	this->identifier=username;
	std::shared_ptr<T> *inner=nullptr;
	if(db_view[item_name]) {
		if constexpr(std::is_same<DT, std::string>::value) {
			inner=new std::shared_ptr<T>(new T((T)(std::string)db_view[item_name].get_string()));
		}else if constexpr(std::is_same<DT, bool>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name].get_bool()));
		}else if constexpr(std::is_same<DT, int32_t>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name].get_int32()));
		}else if constexpr(std::is_same<DT, int64_t>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name].get_int64()));
		}else if constexpr(std::is_same<DT, NEMCUserAuthInfo>::value||std::is_same<DT, NEMCUser>::value||std::is_same<DT, SigningKeyPair>::value) {
			inner=new std::shared_ptr<T>(new T((T)db_view[item_name]));
		}else {
			SPDLOG_CRITICAL("Unknown type for DBValue runtime construction");
			throw std::runtime_error("Unexpected type for FBWhitelist::DBValue<T, DT>::DBValue");
		}
	}
	if(!inner)
		inner=new std::shared_ptr<T>();
	std::shared_ptr<std::shared_ptr<T>> outer=std::shared_ptr<std::shared_ptr<T>>(inner);
	object=outer;
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>& FBWhitelist::DBValue<T, DT>::operator=(T const& target) {
	set(target);
	return *this;
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>& FBWhitelist::DBValue<T, DT>::operator-=(T const& target) {
	if constexpr(std::is_integral<T>::value) {
		*this=(T)*this-target;
		return *this;
	}else{
		std::terminate();
	}
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>& FBWhitelist::DBValue<T, DT>::operator+=(T const& target) {
	if constexpr(std::is_integral<T>::value) {
		*this=(T)*this+target;
		return *this;
	}else{
		std::terminate();
	}
}

template <typename T, typename DT>
void FBWhitelist::DBValue<T, DT>::_set(T const& target) {
	*object=std::make_shared<T>(target);
}

template <typename T, typename DT>
void FBWhitelist::DBValue<T, DT>::set(T const& target) {
	w_lock->lock();
	*object=std::make_shared<T>(target);
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].update_one(bsoncxx::builder::stream::document{}<<"username"<<*identifier<<bsoncxx::builder::stream::finalize, bsoncxx::builder::stream::document{}<<"$set"<<bsoncxx::builder::stream::open_document<<std::string(item_name)<<(DT)**object<<bsoncxx::builder::stream::close_document<<bsoncxx::builder::stream::finalize);
	w_lock->unlock();
	return;
}

template <typename T, typename DT>
void FBWhitelist::DBValue<T, DT>::unset() {
	w_lock->lock();
	*object=nullptr;
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].update_one(bsoncxx::builder::stream::document{}<<"username"<<*identifier<<bsoncxx::builder::stream::finalize, bsoncxx::builder::stream::document{}<<"$unset"<<bsoncxx::builder::stream::open_document<<std::string(item_name)<<false<<bsoncxx::builder::stream::close_document<<bsoncxx::builder::stream::finalize);
	w_lock->unlock();
	return;
}


template <typename T, typename DT>
bool FBWhitelist::DBValue<T, DT>::operator==(T const& target) const {
	if(!*object) {
		return T()==target;
	}
	return **object==target;
}

template <typename T, typename DT>
std::strong_ordering FBWhitelist::DBValue<T, DT>::operator<=>(T const& target) const {
	if constexpr(std::is_integral<T>::value) {
		if(!*object) {
			return std::strong_ordering::less;
		}
		if(**object==target) {
			return std::strong_ordering::equal;
		}else if(**object<target) {
			return std::strong_ordering::less;
		}
		return std::strong_ordering::greater;
	}else{
		std::terminate();
	}
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>::operator T() const {
	if(!*object) {
		// For example, bool() is always false
		return T();
	}
	return **object;
}

template <typename T, typename DT>
FBWhitelist::DBValue<T, DT>::operator Json::Value() const {
	if constexpr (!std::is_integral<T>::value&&!std::is_same<T, std::string>::value) {
		return Json::Value();
	}else{
		if(!*object) {
			// For example, bool() is always false
			return Json::Value(T());
		}
		return Json::Value(**object);
	}
}

template <typename T, typename DT>
T FBWhitelist::DBValue<T, DT>::operator*() const {
	if(!*object) {
		return T();
	}
	return **object;
}

template <typename T, typename DT>
T const* FBWhitelist::DBValue<T, DT>::operator->() const {
	return object->get();
}

template <typename T, typename DT>
bool FBWhitelist::DBValue<T, DT>::stillAlive() const {
	if constexpr(std::is_arithmetic<T>::value) {
		if(!*object) {
			return false;
		}
		uint64_t ed=(uint64_t)**this;
		return time(nullptr)<ed;
	}
	printf("WARNING: stillAlive called for non-calculatable stuff\n");
	return false;
}

template <typename T, typename DT>
void FBWhitelist::RentalServerDBValue<T, DT>::set(T const& target) {
	this->w_lock->lock();
	*(this->object)=std::make_shared<T>(target);
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].update_one(bsoncxx::builder::stream::document{}<<"username"<<*(this->identifier)<<"rentalservers.slotid"<<slotid<<bsoncxx::builder::stream::finalize, bsoncxx::builder::stream::document{}<<"$set"<<bsoncxx::builder::stream::open_document<<fmt::format("rentalservers.$.{}", this->item_name)<<(DT)**(this->object)<<bsoncxx::builder::stream::close_document<<bsoncxx::builder::stream::finalize);
	this->w_lock->unlock();
	return;
}


template <typename T, typename DT>
void FBWhitelist::RentalServerDBValue<T, DT>::unset() {
	this->w_lock->lock();
	*(this->object)=nullptr;
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].update_one(bsoncxx::builder::stream::document{}<<"username"<<*(this->identifier)<<"rentalservers.slotid"<<slotid<<bsoncxx::builder::stream::finalize, bsoncxx::builder::stream::document{}<<"$unset"<<bsoncxx::builder::stream::open_document<<fmt::format("rentalservers.$.{}", this->item_name)<<false<<bsoncxx::builder::stream::close_document<<bsoncxx::builder::stream::finalize);
	this->w_lock->unlock();
	return;
}

FBWhitelist::RentalServerItem FBWhitelist::RentalServerStore::InvalidRentalServer;

std::unordered_map<std::string, FBWhitelist::RentalServerItem>::const_iterator FBWhitelist::RentalServerStore::begin() const {
	return rentalServerMap->begin();
}

std::unordered_map<std::string, FBWhitelist::RentalServerItem>::const_iterator FBWhitelist::RentalServerStore::end() const {
	return rentalServerMap->end();
}

size_t FBWhitelist::RentalServerStore::size() const {
	return rentalServerMap->size();
}

void FBWhitelist::RentalServerStore::erase_slot(std::unordered_map<std::string, RentalServerItem>::iterator &item_iter) {
	return erase_slot(item_iter->first);
}

void FBWhitelist::RentalServerStore::erase_slot(std::string const& key) {
	if(!rentalServerMap->contains(key)) {
		return;
	}
	write_mutex->lock();
	rentalServerMap->erase(key);
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].update_one(document{}<<"username"<<*username<<finalize, document{}<<"$pull"<<open_document<<"rentalservers"<<open_document<<"slotid"<<key<<close_document<<close_document<<finalize);
	write_mutex->unlock();
}

Json::Value FBWhitelist::RentalServerStore::toDescriptiveJSON() const {
	Json::Value ret(Json::ValueType::arrayValue);
	for(auto &i:*rentalServerMap) {
		Json::Value cur;
		if(i.second.lastdate==(uint64_t)0) {
			cur["canchange"]=true;
			cur["ato"]=0;
		}else{
			if(i.second.locked) {
				cur["canchange"]=false;
			}else{
				time_t sugosu=time(nullptr)-i.second.lastdate;
				if(sugosu>2592000) {
					cur["canchange"]=true;
					cur["ato"]=0;
				}else{
					cur["canchange"]=false;
					cur["ato"]=round(((2592000-sugosu)/86400.0)*100.0)/100.0;
				}
			}
		}
		cur["sid"]=i.second.content;
		cur["slotid"]=i.second.slotid;
		cur["locked"]=i.second.locked;
		ret.append(cur);
	}
	return ret;
}

Json::Value FBWhitelist::RentalServerStore::toAdministrativeJSON() const {
	Json::Value ret(Json::ValueType::arrayValue);
	for(auto &i:*rentalServerMap) {
		Json::Value cur;
		cur["sid"]=i.second.content;
		cur["lastdate"]=i.second.lastdate;
		cur["slotid"]=i.second.slotid;
		cur["locked"]=i.second.locked;
		ret.append(cur);
	}
	return ret;
}

FBWhitelist::RentalServerItem& FBWhitelist::RentalServerStore::append_slot() {
	write_mutex->lock();
	std::string slotid;
	do {
		slotid=Utils::generateUUID();
	}while(rentalServerMap->contains(slotid));
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].update_one(document{}<<"username"<<*username<<finalize, document{}<<"$push"<<open_document<<"rentalservers"<<open_document<<"sid"<<""<<"slotid"<<slotid<<"lastdate"<<bsoncxx::types::b_null()<<close_document<<close_document<<finalize);
	RentalServerItem item;
	item.is_valid=true;
	item.content=FBWhitelist::RentalServerDBValue<std::string>("sid", username, slotid, "");
	item.slotid=FBWhitelist::RentalServerDBValue<std::string>("slotid", username, slotid, slotid);
	item.lastdate=FBWhitelist::RentalServerDBValue<uint64_t, int64_t>("lastdate", username, slotid, 0);
	item.locked=FBWhitelist::RentalServerDBValue<bool>("locked", username, slotid, false);
	(*rentalServerMap)[slotid]=item;
	write_mutex->unlock();
	return (*rentalServerMap)[slotid];
}

FBWhitelist::RentalServerItem::operator bool() const {
	return is_valid;
}

FBWhitelist::RentalServerItem& FBWhitelist::RentalServerStore::operator [](std::string const& key) {
	return at(key);
}

FBWhitelist::RentalServerItem& FBWhitelist::RentalServerStore::at(std::string const& key) {
	if(!rentalServerMap->contains(key)) {
		return FBWhitelist::RentalServerStore::InvalidRentalServer;
	}
	return (*rentalServerMap)[key];
}

FBWhitelist::SigningKeyPair::SigningKeyPair(bsoncxx::document::element const& db_item) {
	auto doc_view=db_item.get_document().view();
	private_key=(std::string)doc_view["private"].get_string();
	public_key=(std::string)doc_view["public"].get_string();
}

FBWhitelist::SigningKeyPair::operator bsoncxx::document::view() {
	stored_doc_value=document{}<<"private"<<private_key<<"public"<<public_key<<finalize;
	return stored_doc_value.view();
}

bool FBWhitelist::SigningKeyPair::operator==(FBWhitelist::SigningKeyPair const& value) const {
	return private_key==value.private_key&&public_key==value.public_key;
}

std::unordered_map<std::string, std::shared_ptr<FBWhitelist::User>> FBWhitelist::Whitelist::stored_user_map;
std::mutex FBWhitelist::Whitelist::user_finding_lock;
std::shared_mutex FBWhitelist::Whitelist::user_pool_lock;
unsigned short FBWhitelist::Whitelist::op_count_to_clearance=32;

std::shared_ptr<FBWhitelist::User> FBWhitelist::Whitelist::_findUser(std::string const& username) {
	const std::lock_guard<std::mutex> lock(user_finding_lock);
	try {
		auto client=mongodb_pool.acquire();
		auto user_item=(*client)["fastbuilder"]["whitelist"].find_one(document{}<<"username"<<username<<finalize);
		if(!user_item.has_value()) {
			return nullptr;
		}
		auto useritem=*user_item;
		FBWhitelist::User userobj;
		userobj.user_oid=(std::string)useritem["_id"].get_oid().value.to_string();
		std::shared_ptr<std::string> username_ptr(new std::string(username));
		if(useritem["rentalservers"]) {
			FBWhitelist::RentalServerStore rs_store;
			rs_store.username=username_ptr;
			bsoncxx::array::view rs_arr=(bsoncxx::array::view)useritem["rentalservers"].get_array();
			for(auto &i:rs_arr) {
				FBWhitelist::RentalServerItem subitem;
				subitem.is_valid=true;
				if(!i["slotid"]) continue;
				std::string slotid(i["slotid"].get_string());
				subitem.content=FBWhitelist::RentalServerDBValue<std::string>("sid", username_ptr, slotid, i);
				subitem.slotid=FBWhitelist::RentalServerDBValue<std::string>("slotid", username_ptr, slotid, slotid);
				if(i["lastdate"]&&i["lastdate"].type()!=bsoncxx::type::k_null) {
					subitem.lastdate=FBWhitelist::RentalServerDBValue<uint64_t, int64_t>("lastdate", username_ptr, slotid, i["lastdate"].get_int64());
				}else{
					subitem.lastdate=FBWhitelist::RentalServerDBValue<uint64_t, int64_t>("lastdate", username_ptr, slotid);
				}
				subitem.locked=FBWhitelist::RentalServerDBValue<bool>("locked", username_ptr,slotid, i);
				(*rs_store.rentalServerMap)[slotid]=subitem;
			}
			userobj.rentalservers=rs_store;
		}else{
			FBWhitelist::RentalServerStore rs_store;
			rs_store.username=username_ptr;
			userobj.rentalservers=rs_store;
		}
		for(FBWhitelist::DBValue<bool> *i=(FBWhitelist::DBValue<bool> *)&userobj.username;(void*)i!=(void*)&userobj.rate_limit_counter;i++) {
			// ^ The template of the pointer doesn't matter
			i->load(username_ptr, useritem);
		}
		return std::make_shared<FBWhitelist::User>(userobj);
	}catch(std::exception const& err) {
		SPDLOG_CRITICAL("Database Error on USER {}: {}", username, err.what());
		abort();
	}
}

std::shared_ptr<FBWhitelist::User> FBWhitelist::Whitelist::acquireUser(std::string const& username) {
	std::shared_lock<std::shared_mutex> upl(user_pool_lock);
	if(stored_user_map.contains(username)) {
		return stored_user_map[username];
	}
	std::shared_ptr<FBWhitelist::User> userptr=_findUser(username);
	if(!userptr) {
		return nullptr;
	}
	upl.unlock();
	if(!op_count_to_clearance) {
		std::unique_lock<std::shared_mutex> unique_l(user_pool_lock);
		// Empty some of the cache
		if(stored_user_map.size()>64) {
			for(int i=0;i<32;i++) {
				auto const& victim=std::next(std::begin(stored_user_map), Utils::safeRandomNumber()%(stored_user_map.size()));
				if(!*victim->second->keep_reference) {
					stored_user_map.erase(victim);
				}
			}
		}
		op_count_to_clearance=32;
	}else{
		op_count_to_clearance--;
	}
	stored_user_map[username]=userptr;
	return userptr;
}

std::optional<FBWhitelist::User> FBWhitelist::Whitelist::findUser(std::string const& username) {
	std::shared_ptr<FBWhitelist::User> ac_ptr=acquireUser(username);
	if(!ac_ptr) {
		return std::nullopt;
	}
	return *ac_ptr;
}

template <typename T, typename DT>
FBWhitelist::RentalServerDBValue<T, DT>& FBWhitelist::RentalServerDBValue<T, DT>::operator=(T const& target) {
	return (RentalServerDBValue&)FBWhitelist::DBValue<T, DT>::operator=(target);
}

template <typename T, typename DT>
FBWhitelist::RentalServerDBValue<T, DT>& FBWhitelist::RentalServerDBValue<T, DT>::operator+=(T const& target) {
	return (RentalServerDBValue&)FBWhitelist::DBValue<T, DT>::operator+=(target);
}

template <typename T, typename DT>
FBWhitelist::RentalServerDBValue<T, DT>& FBWhitelist::RentalServerDBValue<T, DT>::operator-=(T const& target) {
	return (RentalServerDBValue&)FBWhitelist::DBValue<T, DT>::operator-=(target);
}

template <typename T, typename DT>
bool FBWhitelist::RentalServerDBValue<T, DT>::operator==(T const& target) const {
	return FBWhitelist::DBValue<T, DT>::operator==(target);
}

template <typename T, typename DT>
std::strong_ordering FBWhitelist::RentalServerDBValue<T, DT>::operator<=>(T const& target) const {
	return FBWhitelist::DBValue<T, DT>::operator<=>(target);
}

template <typename T, typename DT>
FBWhitelist::RentalServerDBValue<T, DT>::operator T() const {
	return FBWhitelist::DBValue<T, DT>::operator T();
}

template <typename T, typename DT>
FBWhitelist::RentalServerDBValue<T, DT>::operator Json::Value() const {
	return FBWhitelist::DBValue<T, DT>::operator Json::Value();
}

template <typename T, typename DT>
T FBWhitelist::RentalServerDBValue<T, DT>::operator *() const {
	return FBWhitelist::DBValue<T, DT>::operator*();
}

template <typename T, typename DT>
T const *FBWhitelist::RentalServerDBValue<T, DT>::operator->() const {
	return FBWhitelist::DBValue<T, DT>::operator->();
}

template <typename T, typename DT>
bool FBWhitelist::RentalServerDBValue<T, DT>::has_value() const {
	return FBWhitelist::DBValue<T, DT>::has_value();
}

std::optional<FBWhitelist::User> FBWhitelist::Whitelist::createUser(std::string const& username, std::string const& password) {
	if(findUser(username).has_value()) {
		return std::nullopt;
	}
	user_finding_lock.lock();
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].insert_one(document{}<<"cn"<<"" <<"username"<<username <<"banned"<<false <<"password"<<password <<"owns"<<open_array<<0<<close_array <<"isAfterPhoenix"<<true <<"free"<<true <<finalize);
	user_finding_lock.unlock();
	return findUser(username);
}

void FBWhitelist::Whitelist::dropUser(std::string const& username) {
	user_finding_lock.lock();
	if(stored_user_map.contains(username)) {
		stored_user_map.erase(username);
	}
	auto client=mongodb_pool.acquire();
	(*client)["fastbuilder"]["whitelist"].delete_one(document{}<<"username"<<username<<finalize);
	user_finding_lock.unlock();
}

void FBWhitelist::Whitelist::emptyCache() {
	user_finding_lock.lock();
	stored_user_map.clear();
	user_finding_lock.unlock();
}