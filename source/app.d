import std.stdio;
import ip2proxy;

int main() {
	string db = "./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN.BIN";
	auto prox = new ip2proxy();
	
	if (prox.open(db) == 0) {
		auto ip = "199.83.103.79";
		
		writeln("ModuleVersion: ", prox.module_version());
		writeln("PackageVersion: ", prox.package_version());
		writeln("DatabaseVersion: ", prox.database_version());
		
		// functions for individual fields
		writeln("IsProxy: ", prox.is_proxy(ip));
		writeln("ProxyType: ", prox.get_proxy_type(ip));
		writeln("CountryShort: ", prox.get_country_short(ip));
		writeln("CountryLong: ", prox.get_country_long(ip));
		writeln("Region: ", prox.get_region(ip));
		writeln("City: ", prox.get_city(ip));
		writeln("ISP: ", prox.get_isp(ip));
		writeln("Domain: ", prox.get_domain(ip));
		writeln("UsageType: ", prox.get_usage_type(ip));
		writeln("ASN: ", prox.get_asn(ip));
		writeln("AS: ", prox.get_as(ip));
		writeln("LastSeen: ", prox.get_last_seen(ip));
		
		// function for all fields
		auto all = prox.get_all(ip);
		writeln("isProxy: ", all["isProxy"]);
		writeln("ProxyType: ", all["ProxyType"]);
		writeln("CountryShort: ", all["CountryShort"]);
		writeln("CountryLong: ", all["CountryLong"]);
		writeln("Region: ", all["Region"]);
		writeln("City: ", all["City"]);
		writeln("ISP: ", all["ISP"]);
		writeln("Domain: ", all["Domain"]);
		writeln("UsageType: ", all["UsageType"]);
		writeln("ASN: ", all["ASN"]);
		writeln("AS: ", all["AS"]);
		writeln("LastSeen: ", all["LastSeen"]);
	}
	else {
		writeln("Error reading BIN file.");
	}
	prox.close();
	
	return 0;
}
