# IP2Proxy D Library

This D library allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES) and residential (RES). It lookup the proxy IP address from **IP2Proxy BIN Data** file. This data file can be downloaded at

* Free IP2Proxy BIN Data: http://lite.ip2location.com
* Commercial IP2Proxy BIN Data: https://www.ip2location.com/database/ip2proxy

As an alternative, this component can also call the IP2Proxy Web Service. This requires an API key. If you don't have an existing API key, you can subscribe for one at the below:

https://www.ip2location.com/web-service/ip2proxy

## Installation

To install this library using dub:

```
"dependencies": {
    "ip2proxy-d": "~master"
}
```

## QUERY USING THE BIN FILE

## Methods
Below are the methods supported in this library.

|Method Name|Description|
|---|---|
|open|Open the IP2Proxy BIN data for lookup.|
|close|Close and reset metadata.|
|package_version|Get the package version (1 to 11 for PX1 to PX11 respectively).|
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
|get_provider|Return the provider of the proxy.|

## Usage

```d
import std.stdio;
import ip2proxy : ip2proxy;

int main() {
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
	
	return 0;
}
```

## QUERY USING THE IP2PROXY PROXY DETECTION WEB SERVICE

## Methods
Below are the methods supported in this class.

|Method Name|Description|
|---|---|
|open(const string apikey, const string apipackage, bool usessl = true)| Expects 3 input parameters:<ol><li>IP2Proxy API Key.</li><li>Package (PX1 - PX11)</li></li><li>Use HTTPS or HTTP</li></ol>|
|lookup(const string ipaddress)|Query IP address. This method returns a JSONValue containing the proxy info. <ul><li>countryCode</li><li>countryName</li><li>regionName</li><li>cityName</li><li>isp</li><li>domain</li><li>usageType</li><li>asn</li><li>as</li><li>lastSeen</li><li>threat</li><li>proxyType</li><li>isProxy</li><li>provider</li><ul>|
|get_credit()|This method returns the web service credit balance in a JSONValue.|

## Usage

```d
import std.stdio;
import std.conv : to;
import ip2proxywebservice : ip2proxywebservice;

int main() {
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
```

### Proxy Type

|Proxy Type|Description|
|---|---|
|VPN|Anonymizing VPN services|
|TOR|Tor Exit Nodes|
|PUB|Public Proxies|
|WEB|Web Proxies|
|DCH|Hosting Providers/Data Center|
|SES|Search Engine Robots|
|RES|Residential Proxies [PX10+]|

### Usage Type

|Usage Type|Description|
|---|---|
|COM|Commercial|
|ORG|Organization|
|GOV|Government|
|MIL|Military|
|EDU|University/College/School|
|LIB|Library|
|CDN|Content Delivery Network|
|ISP|Fixed Line ISP|
|MOB|Mobile ISP|
|DCH|Data Center/Web Hosting/Transit|
|SES|Search Engine Spider|
|RSV|Reserved|

### Threat Type

|Threat Type|Description|
|---|---|
|SPAM|Spammer|
|SCANNER|Security Scanner or Attack|
|BOTNET|Spyware or Malware|
