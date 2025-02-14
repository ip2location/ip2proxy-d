# Quickstart

## Dependencies

This library requires IP2Proxy BIN database to function. You may download the BIN database at

-   IP2Proxy LITE BIN Data (Free): <https://lite.ip2location.com>
-   IP2Proxy Commercial BIN Data (Comprehensive):
    <https://www.ip2location.com>

## Installation

To install this library using dub:

```
"dependencies": {
    "ip2proxy-d": "~master"
}
```

## Sample Codes

### Query geolocation information from BIN database

You can query the geolocation information from the IP2Proxy BIN database as below:

```d
import std.stdio;
import ip2proxy : ip2proxy;

int main() {
	string db = "./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL-PROVIDER-FRAUDSCORE.BIN";
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
		writeln("FraudScore: ", prox.get_fraud_score(ip));
		
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
		writeln("FraudScore: ", all["FraudScore"]);
	}
	else {
		writeln("Error reading BIN file.");
	}
	prox.close();
	
	return 0;
}
```