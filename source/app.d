import std.stdio;
import std.conv : to;
import ip2proxy : ip2proxy;
import ip2proxywebservice : ip2proxywebservice;

int main() {
	// Query using BIN file
	string db = "./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER.BIN";
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
		writeln("Threat: ", prox.get_threat(ip));
		writeln("Provider: ", prox.get_provider(ip));
		
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
		writeln("Threat: ", all["Threat"]);
		writeln("Provider: ", all["Provider"]);
	}
	else {
		writeln("Error reading BIN file.");
	}
	prox.close();
	
	// Query using web service
	auto ip = "8.8.8.8";
	auto apikey = "YOUR_API_KEY";
	auto apipackage = "PX11";
	auto usessl = true;
	
	auto ws = new ip2proxywebservice();
	
	ws.open(apikey, apipackage, usessl);
	
	auto result = ws.lookup(ip);
	
	if ("response" in result && result["response"].str == "OK") {
		writefln("countryCode: %s", ("countryCode" in result) ? result["countryCode"].str : "");
		writefln("countryName: %s", ("countryName" in result) ? result["countryName"].str : "");
		writefln("regionName: %s", ("regionName" in result) ? result["regionName"].str : "");
		writefln("cityName: %s", ("cityName" in result) ? result["cityName"].str : "");
		writefln("isp: %s", ("isp" in result) ? result["isp"].str : "");
		writefln("domain: %s", ("domain" in result) ? result["domain"].str : "");
		writefln("usageType: %s", ("usageType" in result) ? result["usageType"].str : "");
		writefln("asn: %s", ("asn" in result) ? result["asn"].str : "");
		writefln("as: %s", ("as" in result) ? result["as"].str : "");
		writefln("lastSeen: %s", ("lastSeen" in result) ? result["lastSeen"].str : "");
		writefln("proxyType: %s", ("proxyType" in result) ? result["proxyType"].str : "");
		writefln("threat: %s", ("threat" in result) ? result["threat"].str : "");
		writefln("isProxy: %s", ("isProxy" in result) ? result["isProxy"].str : "");
		writefln("provider: %s", ("provider" in result) ? result["provider"].str : "");
	}
	else if ("response" in result) {
		writefln("Error: %s", result["response"]);
	}
	else {
		writeln("Error: Unknown error.");
	}
	
	auto result2 = ws.get_credit();
	
	if ("response" in result2) {
		writefln("Credit balance: %d", to!int(result2["response"].str));
	}
	else {
		writeln("Error: Unknown error.");
	}
	
	return 0;
}
