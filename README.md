# IP2Proxy D Library

This D library allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: http://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy


## Installation

To install this library using dub:

```
"dependencies": {
    "ip2proxy-d": "~master"
}
```

## Methods
Below are the methods supported in this library.

|Method Name|Description|
|---|---|
|open|Open the IP2Proxy BIN data for lookup.|
|close|Close and reset metadata.|
|package_version|Get the package version (1 to 10 for PX1 to PX10 respectively).|
|module_version|Get the module version.|
|database_version|Get the database version.|
|is_proxy|Check whether if an IP address was a proxy. Returned value:<ul><li>-1 : errors</li><li>0 : not a proxy</li><li>1 : a proxy</li><li>2 : a data center IP address or search engine robot</li></ul>|
|get_all|Return the proxy information in an array.|
|get_proxy_type|Return the proxy type. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of proxy types supported.|
|get_country_short|Return the ISO3166-1 country code (2-digits) of the proxy.|
|get_country_long|Return the ISO3166-1 country name of the proxy.|
|get_region|Return the ISO3166-2 region name of the proxy. Please visit <a href="https://www.ip2location.com/free/iso3166-2" target="_blank">ISO3166-2 Subdivision Code</a> for the information of ISO3166-2 supported.|
|get_city|Return the city name of the proxy.|
|get_isp|Return the ISP name of the proxy.|
|get_domain|Return the domain name of the proxy.|
|get_usage_type|Return the usage type classification of the proxy. Please visit <a href="https://www.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential" target="_blank">IP2Location</a> for the list of usage types supported.|
|get_asn|Return the autonomous system number of the proxy.|
|get_as|Return the autonomous system name of the proxy.|
|get_last_seen|Return the number of days that the proxy was last seen.|
|get_threat|Return the threat type of the proxy.|

## Usage

```d
import std.stdio;
import ip2proxy;

int main() {
	string db = "./IP2PROXY-IP-PROXYTYPE-COUNTRY-REGION-CITY-ISP-DOMAIN-USAGETYPE-ASN-LASTSEEN-THREAT-RESIDENTIAL.BIN";
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
	}
	else {
		writeln("Error reading BIN file.");
	}
	prox.close();
	
	return 0;
}
```
