import std.uri;
import std.regex;
import std.stdio;
import std.net.curl;
import std.json;

class ip2proxywebservice {
	private string _apikey = "";
	private string _apipackage = "";
	private bool _usessl = true;
	private const string baseurl = "api.ip2proxy.com/";
	
	// constructor
	public this() {
	}
	
	// initialize with API key and package
	public void open(const string apikey, const string apipackage, bool usessl = true) {
		_apikey = apikey;
		_apipackage = apipackage;
		_usessl = usessl;
		checkparams();
	}
	
	// check params
	public void checkparams() {
		auto apikeypattern = ctRegex!(`^[\dA-Z]{10}$`);
		auto apipackagepattern = ctRegex!(`^PX\d+$`);
		
		if (!matchFirst(_apikey, apikeypattern) && _apikey != "demo") {
			throw new Exception("Invalid API key.");
		}
		if (!matchFirst(_apipackage, apipackagepattern)) {
			throw new Exception("Invalid package name.");
		}
	}
	
	// query web service for proxy information
	public auto lookup(const string ipaddress) {
		checkparams(); // check here in case user haven't called open yet
		auto protocol  = (_usessl) ? "https" : "http";
		auto url = protocol ~ "://" ~ baseurl ~ "?key=" ~ _apikey ~ "&package=" ~ _apipackage ~ "&ip=" ~ ipaddress.encode;
		auto content = get(url);
		JSONValue j = parseJSON(content);
		return j;
	}
	
	// check web service credit balance
	public auto get_credit() {
		checkparams(); // check here in case user haven't called open yet
		auto protocol  = (_usessl) ? "https" : "http";
		auto url = protocol ~ "://" ~ baseurl ~ "?key=" ~ _apikey ~ "&check=true";
		auto content = get(url);
		JSONValue j = parseJSON(content);
		return j;
	}
}
