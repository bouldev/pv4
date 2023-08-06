#include "products.h"

struct FixedSlotProduct:Product {
	virtual unsigned int product_id() {
		return 1;
	}
	
	virtual std::string product_name() {
		return "固定 SLOT";
	}
	
	virtual std::string product_name_en() {
		return "Fixed slot";
	}
	
	virtual unsigned int price() {
		return 32;
	}
	
	virtual std::string product_detail() {
		return "用于在<b>用户信息页面</b>设置租赁服号的SLOT。<br/>添加后只可修改一次，完成后永久变为只读。";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free) {
			return true;
		}
		if((bool)user.expiration_date) {
			return true;
		}
		return false;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		user.rentalservers.append_slot().locked=true;
	}
};

struct SlotProduct : Product {
	virtual unsigned int product_id() {
		return 2;
	}
	
	virtual std::string product_name() {
		return "可变 SLOT";
	}
	
	virtual std::string product_name_en() {
		return "Modifiable slot";
	}
	
	virtual unsigned int price() {
		return 80;
	}
	
	virtual std::string product_detail() {
		return "用于在<b>用户信息页面</b>设置租赁服号的SLOT。<br/>添加后每次修改后需要冷却一个月方可修改。";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free) {
			return true;
		}
		if((bool)user.expiration_date) {
			return true;
		}
		return false;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		user.rentalservers.append_slot();
	}
};

struct MonthlyPlanNewUserProduct : Product {
	virtual unsigned int product_id() {
		return 3;
	}
	
	virtual std::string product_name() {
		return "1 个月服务使用权 (+1 可变SLOT)";
	}
	
	virtual std::string product_name_en() {
		return "1 month subscription (+1 modifiable slot)";
	}
	
	virtual unsigned int price() {
		return 45;
	}
	
	virtual bool no_multi_add() {
		return true;
	}
	
	virtual std::string product_detail() {
		return "1 个月的 PhoenixBuilder 租赁服使用权限，附1个可变SLOT。";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free) {
			return false;
		}
		if((bool)user.expiration_date) {
			return false;
		}
		return true;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		user.expiration_date=time(nullptr)+30*86400;
		user.rentalservers.append_slot();
	}
};

struct MonthlyPlan1MonthProduct : Product {
	virtual unsigned int product_id() {
		return 4;
	}
	
	virtual std::string product_name() {
		return "1 个月服务使用权";
	}
	
	virtual std::string product_name_en() {
		return "1 month subscription";
	}
	
	virtual unsigned int price() {
		return 32;
	}
	
	virtual std::string product_detail() {
		return "1 个月的 PhoenixBuilder 租赁服使用权限，可以叠加（也可以多个加入购物车）";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free) {
			return false;
		}
		if((bool)user.expiration_date) {
			return true;
		}
		return false;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		unsigned int days=30;
		time_t last=user.expiration_date.stillAlive()?user.expiration_date+days*86400:time(nullptr)+days*86400;
		user.expiration_date=last;
	}
};

struct MonthlyPlan3MonthsProduct : Product {
	virtual unsigned int product_id() {
		return 5;
	}
	
	virtual std::string product_name() {
		return "3 个月服务使用权";
	}
	
	virtual std::string product_name_en() {
		return "3 months subscription";
	}
	
	virtual unsigned int price() {
		return 92;
	}
	
	virtual std::string product_detail() {
		return "3 个月(91天)的 PhoenixBuilder 租赁服使用权限，可以叠加（也可以多个加入购物车）";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free) {
			return false;
		}
		if((bool)user.expiration_date) {
			return true;
		}
		return false;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		unsigned int days=91;
		time_t last=user.expiration_date.stillAlive()?user.expiration_date+days*86400:time(nullptr)+days*86400;
		user.expiration_date=last;
	}
};

struct MonthlyPlan2YearsProduct : Product {
	virtual unsigned int product_id() {
		return 6;
	}
	
	virtual std::string product_name() {
		return "2 年服务使用权";
	}
	
	virtual std::string product_name_en() {
		return "2 years subscription";
	}
	
	virtual unsigned int price() {
		return 750;
	}
	
	virtual std::string product_detail() {
		return "2 年(730 天)的 PhoenixBuilder 租赁服使用权限，可以叠加（也可以多个加入购物车）。我们的服务随时可能结束，请慎重购买。";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free) {
			return false;
		}
		if((bool)user.expiration_date) {
			return true;
		}
		return false;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		unsigned int days=365*2;
		time_t last=user.expiration_date.stillAlive()?user.expiration_date+days*86400:time(nullptr)+days*86400;
		user.expiration_date=last;
	}
};

struct DropHelperFreeProduct : Product {
	virtual unsigned int product_id() {
		return 7;
	}
	
	virtual std::string product_name() {
		return "丢弃辅助用户 (免费)";
	}
	
	virtual std::string product_name_en() {
		return "";
	}
	
	virtual unsigned int price() {
		return 0;
	}
	
	virtual bool forbid_cart() {
		return true;
	}
	
	virtual std::string product_detail() {
		return "丢弃您的辅助用户, 免费丢弃后有 1 个月的冷却期。";
	}
	
	virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free||(bool)user.expiration_date) {
			if(!user.next_drop_date.has_value()||user.next_drop_date<(uint64_t)time(nullptr)) {
				return true;
			}
		}
		return false;
	}
	
	virtual void execute_on(FBWhitelist::User &user) {
		user.next_drop_date=(uint64_t)time(nullptr)+(uint64_t)3600*24*30;
		user.nemc_temp_info.unset();
		user.nemc_access_info.unset();
	}
};

struct DropHelperProduct : Product {
	virtual unsigned int product_id() {
		return 8;
	}
	
	virtual std::string product_name() {
		return "丢弃辅助用户";
	}
	
	virtual std::string product_name_en() {
		return "";
	}
	
	virtual unsigned int price() {
		return 32;
	}
	
	virtual std::string product_detail() {
		return "丢弃您的辅助用户。";
	}
	
	virtual bool forbid_cart() {
		return true;
	}
	
	/*virtual bool check_on(FBWhitelist::User &user) {
		if(!user.free||(bool)user.expiration_date) {
			if(!user.next_drop_date.has_value()||user.next_drop_date<(uint64_t)time(nullptr)) {
				return false;
			}else{
				return true;
			}
		}
		return false;
	}*/
	
	virtual void execute_on(FBWhitelist::User &user) {
		user.nemc_temp_info.unset();
		user.nemc_access_info.unset();
	}
};

static std::vector<Product *> _pv4_products_all_products={
	new FixedSlotProduct,
	new SlotProduct,
	new MonthlyPlanNewUserProduct,
	new MonthlyPlan1MonthProduct,
	new MonthlyPlan3MonthsProduct,
	new MonthlyPlan2YearsProduct,
	new DropHelperFreeProduct,
	new DropHelperProduct
};

extern "C" std::vector<Product *> const& all_products() {
	return _pv4_products_all_products;
}

extern "C" void _products_destruct() {
	for(Product *i:_pv4_products_all_products) {
		delete i;
	}
}

Json::Value Product::toJSON() {
	Json::Value currentVal;
	currentVal["product_id"]=product_id();
	currentVal["product_name"]=product_name();
	currentVal["price"]=price();
	currentVal["product_detail"]=product_detail();
	currentVal["card_only"]=card_only();
	currentVal["no_multi_add"]=no_multi_add();
	return currentVal;
}