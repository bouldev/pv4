#include <string>
#include "whitelist.h"

struct Product {
	virtual unsigned int product_id()=0;
	virtual std::string product_name()=0;
	virtual bool forbid_cart() { return false; }
	virtual unsigned int price()=0;
	virtual std::string product_detail()=0;
	virtual bool no_multi_add() { return false; }
	virtual bool card_only() { return false; }
	virtual bool check_on(FBWhitelist::User &user) { return true; }
	virtual void execute_on(FBWhitelist::User &user) {}
	virtual Json::Value toJSON();
};

extern "C" std::vector<Product *> const& all_products();