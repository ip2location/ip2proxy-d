import std.regex;
import std.stdio;
import std.file;
import std.mmfile;
import std.bitmanip;
import std.bigint;
import std.socket;
import std.conv;

protected struct ip2proxymeta {
	ubyte databasetype;
	ubyte databasecolumn;
	ubyte databaseday;
	ubyte databasemonth;
	ubyte databaseyear;
	uint ipv4databasecount;
	uint ipv4databaseaddr;
	uint ipv6databasecount;
	uint ipv6databaseaddr;
	uint ipv4indexbaseaddr;
	uint ipv6indexbaseaddr;
	uint ipv4columnsize;
	uint ipv6columnsize;
}

protected struct ip2proxyrecord {
	string country_short = "-";
	string country_long = "-";
	string region = "-";
	string city = "-";
	string isp = "-";
	string proxy_type = "-";
	byte is_proxy = -1;
}

protected struct ipv {
	uint iptype = 0;
	BigInt ipnum = BigInt("0");
	uint ipindex = 0; 
}

const ubyte[5] COUNTRY_POSITION = [0, 2, 3, 3, 3];
const ubyte[5] REGION_POSITION = [0, 0, 0, 4, 4];
const ubyte[5] CITY_POSITION = [0, 0, 0, 5, 5];
const ubyte[5] ISP_POSITION = [0, 0, 0, 0, 6];
const ubyte[5] PROXYTYPE_POSITION = [0, 0, 2, 2, 2];

protected const string MODULE_VERSION = "1.0.0";

protected const BigInt MAX_IPV4_RANGE = BigInt("4294967295");
protected const BigInt MAX_IPV6_RANGE = BigInt("340282366920938463463374607431768211455");

protected const uint COUNTRYSHORT = 0x00001;
protected const uint COUNTRYLONG = 0x00002;
protected const uint REGION = 0x00004;
protected const uint CITY = 0x00008;
protected const uint ISP = 0x00010;
protected const uint PROXYTYPE = 0x00020;
protected const uint ISPROXY = 0x00040;

protected const uint ALL = COUNTRYSHORT | COUNTRYLONG | REGION | CITY | ISP | PROXYTYPE | ISPROXY;

protected const string MSG_NOT_SUPPORTED = "NOT SUPPORTED";
protected const string MSG_INVALID_IP = "INVALID IP ADDRESS";
protected const string MSG_MISSING_FILE = "MISSING FILE";
protected const string MSG_IPV6_UNSUPPORTED = "IPV6 ADDRESS MISSING IN IPV4 BIN";

class ip2proxy {
	protected MmFile db;
	private string binfile = "";
	private ip2proxymeta meta;
	private bool metaok = false;
	
	private uint country_position_offset;
	private uint region_position_offset;
	private uint city_position_offset;
	private uint isp_position_offset;
	private uint proxytype_position_offset;
	
	private bool country_enabled;
	private bool region_enabled;
	private bool city_enabled;
	private bool isp_enabled;
	private bool proxytype_enabled;
	
	// constructor
	public this() {
	}
	
	// initialize with BIN file
	public byte open(const string binpath) {
		binfile = binpath;
		close(); // reset
		return readmeta();
	}
	
	// get version of module
	public string module_version() {
		return MODULE_VERSION;
	}
	
	// get package version
	public string package_version() {
		return to!string(meta.databasetype);
	}
	
	// get database version
	public string database_version() {
		return "20" ~ to!string(meta.databaseyear) ~ "." ~ to!string(meta.databasemonth) ~ "." ~ to!string(meta.databaseday);
	}
	
	// reset
	public byte close() {
		meta.databasetype = 0;
		meta.databasecolumn = 0;
		meta.databaseyear = 0;
		meta.databasemonth = 0;
		meta.databaseday = 0;
		meta.ipv4databasecount = 0;
		meta.ipv4databaseaddr = 0;
		meta.ipv6databasecount = 0;
		meta.ipv6databaseaddr = 0;
		meta.ipv4indexbaseaddr = 0;
		meta.ipv6indexbaseaddr = 0;
		meta.ipv4columnsize = 0;
		meta.ipv6columnsize = 0;
		metaok = false;
		country_position_offset = 0;
		region_position_offset = 0;
		city_position_offset = 0;
		isp_position_offset = 0;
		proxytype_position_offset = 0;
		country_enabled = false;
		region_enabled = false;
		city_enabled = false;
		isp_enabled = false;
		proxytype_enabled = false;
		
		return 0;
	}
	
	// read string
	private string readstr(uint index) {
		uint pos = index + 1;
		ubyte len = cast(ubyte)db[index]; // get length of string
		char[] stuff = cast(char[])db[pos .. (pos + len)];
		return to!string(stuff);
	}
	
	// read unsigned 32-bit integer
	private uint readuint(uint index) {
		uint pos = index - 1;
		uint result = 0;
		for (int x = 0; x < 4; x++) {
			uint tiny = cast(ubyte)db[pos + x];
			result += (tiny << (8 * x));
		}
		return result;
	}
	
	// read unsigned 128-bit integer
	private BigInt readuint128(uint index) {
		uint pos = index - 1;
		BigInt result = BigInt("0");
		
		for (int x = 0; x < 16; x++) {
			BigInt biggie = cast(ubyte)db[pos + x];
			result += (biggie << (8 * x));
		}
		
		return result;
	}
	
	// read float
	private float readfloat(uint index) {
		uint pos = index - 1;
		ubyte[4] fl;
		float result = 0.0;
		for (int x = 0; x < 4; x++) {
			fl[x] = cast(ubyte)db[pos + x];
		}
		
		result = littleEndianToNative!float(fl);
		return result;
	}
	
	// read BIN file metadata
	private byte readmeta() {
		if (binfile.length == 0) {
			writeln("BIN file path cannot be blank.");
			return -1;
		}
		else if (!exists(binfile)) {
			writeln("BIN file does not exists.");
			return -1;
		}
		try {
			db = new MmFile(binfile);
			
			meta.databasetype = db[0];
			meta.databasecolumn = db[1];
			meta.databaseyear = db[2];
			meta.databasemonth = db[3];
			meta.databaseday = db[4];
			meta.ipv4databasecount =  readuint(6);
			meta.ipv4databaseaddr =  readuint(10);
			meta.ipv6databasecount =  readuint(14);
			meta.ipv6databaseaddr =  readuint(18);
			meta.ipv4indexbaseaddr =  readuint(22);
			meta.ipv6indexbaseaddr =  readuint(26);
			meta.ipv4columnsize = meta.databasecolumn << 2; // 4 bytes each column
			meta.ipv6columnsize = 16 + ((meta.databasecolumn - 1) << 2); // 4 bytes each column, except IPFrom column which is 16 bytes
			
			uint dbt = meta.databasetype;
			
			// since both IPv4 and IPv6 use 4 bytes for the below columns, can just do it once here
			country_position_offset = (COUNTRY_POSITION[dbt] != 0) ? (COUNTRY_POSITION[dbt] - 1) << 2 : 0;
			region_position_offset = (REGION_POSITION[dbt] != 0) ? (REGION_POSITION[dbt] - 1) << 2 : 0;
			city_position_offset = (CITY_POSITION[dbt] != 0) ? (CITY_POSITION[dbt] - 1) << 2 : 0;
			isp_position_offset = (ISP_POSITION[dbt] != 0) ? (ISP_POSITION[dbt] - 1) << 2 : 0;
			proxytype_position_offset = (PROXYTYPE_POSITION[dbt] != 0) ? (PROXYTYPE_POSITION[dbt] - 1) << 2 : 0;
			
			country_enabled = (COUNTRY_POSITION[dbt] != 0) ? true : false;
			region_enabled = (REGION_POSITION[dbt] != 0) ? true : false;
			city_enabled = (CITY_POSITION[dbt] != 0) ? true : false;
			isp_enabled = (ISP_POSITION[dbt] != 0) ? true : false;
			proxytype_enabled = (PROXYTYPE_POSITION[dbt] != 0) ? true : false;
			
			metaok = true;
		}
		catch (FileException e) {
			return -1;
		}
		return 0;
	}
	
	// determine IP type
	private ipv checkip(const string ipaddress) {
		ipv ipdata;
		const char[] ip = ipaddress;
		try {
			auto results = getAddressInfo(ipaddress, AddressInfoFlags.NUMERICHOST);
			
			if (results.length && results[0].family == AddressFamily.INET) {
				auto ctr = ctRegex!(`^\d+\.\d+\.\d+\.\d+$`);
				auto c2 = matchFirst(ipaddress, ctr);
				if (c2.empty) {
					ipdata.iptype = 0;
					return ipdata;
				}
				ipdata.iptype = 4;
				uint ipno = new InternetAddress(ip, 80).addr();
				ipdata.ipnum = ipno;
				if (meta.ipv4indexbaseaddr > 0) {
					ipdata.ipindex = ((ipno >> 16) << 3) + meta.ipv4indexbaseaddr;
				}
			}
			else if (results.length && results[0].family == AddressFamily.INET6) {
				ipdata.iptype = 6;
				ubyte[16] ipno = new Internet6Address(ip, 80).addr();
				for (int x = 15, y = 0; x >= 0; x--, y++) {
					BigInt biggie = ipno[x];
					ipdata.ipnum += (biggie << (8 * y));
				}
				if (meta.ipv6indexbaseaddr > 0) {
					ipdata.ipindex = (((ipno[0] << 8) + ipno[1]) << 3) + meta.ipv6indexbaseaddr;
				}
				
				// check special case where IPv4 address in IPv6 format (::ffff:0.0.0.0 or ::ffff:00:00)
				if (ipno[0] == 0 && ipno[1] == 0 && ipno[2] == 0 && ipno[3] == 0 && ipno[4] == 0 && ipno[5] == 0 && ipno[6] == 0 && ipno[7] == 0 && ipno[8] == 0 && ipno[9] == 0 && ipno[10] == 255 && ipno[11] == 255) {
					ipdata.iptype = 4;
					uint ipno2 = (ipno[12] << 24) + (ipno[13] << 16) + (ipno[14] << 8) + ipno[15];
					ipdata.ipnum = ipno2;
					if (meta.ipv4indexbaseaddr > 0) {
						ipdata.ipindex = ((ipno2 >> 16) << 3) + meta.ipv4indexbaseaddr;
					}
				}
			}
		}
		catch (Exception e) {
			ipdata.iptype = 0;
		}
		return ipdata;
	}
	
	// populate record with message
	private ip2proxyrecord loadmessage(const string mesg) {
		ip2proxyrecord x;
		
		foreach (i, ref part; x.tupleof) {
			static if (is(typeof(part) == string)) {
				part = mesg;
			}
		}
		return x;
	}
	
	// for debugging purposes
	public void printrecord(ip2proxyrecord x) {
		foreach (i, ref part; x.tupleof) {
			static if (is(typeof(part) == string)) {
				writefln("%s: %s", __traits(identifier, x.tupleof[i]), part);
			}
			else {
				writefln("%s: %d", __traits(identifier, x.tupleof[i]), part);
			}
		}
	}
	
	// get all fields
	public auto get_all(const string ipaddress) {
		auto data = query(ipaddress, ALL);
		
		string[string] x;
		
		x["isProxy"] = to!string(data.is_proxy);
		x["ProxyType"] = data.proxy_type;
		x["CountryShort"] = data.country_short;
		x["CountryLong"] = data.country_long;
		x["Region"] = data.region;
		x["City"] = data.city;
		x["ISP"] = data.isp;
		
		return x;
	}
	
	// get country code
	public auto get_country_short(const string ipaddress) {
		auto data = query(ipaddress, COUNTRYSHORT);
		return data.country_short;
	}
	
	// get country name
	public auto get_country_long(const string ipaddress) {
		auto data = query(ipaddress, COUNTRYLONG);
		return data.country_long;
	}
	
	// get region
	public auto get_region(const string ipaddress) {
		auto data = query(ipaddress, REGION);
		return data.region;
	}
	
	// get city
	public auto get_city(const string ipaddress) {
		auto data = query(ipaddress, CITY);
		return data.city;
	}
	
	// get ISP
	public auto get_isp(const string ipaddress) {
		auto data = query(ipaddress, ISP);
		return data.isp;
	}
	
	// get proxy type
	public auto get_proxy_type(const string ipaddress) {
		auto data = query(ipaddress, PROXYTYPE);
		return data.proxy_type;
	}
	
	// is proxy
	public auto is_proxy(const string ipaddress) {
		auto data = query(ipaddress, ISPROXY);
		return data.is_proxy;
	}
	
	// main query
	private auto query(const string ipaddress, uint mode) {
		auto x = loadmessage(MSG_NOT_SUPPORTED); // default message
		
		// read metadata
		if (!metaok) {
			x = loadmessage(MSG_MISSING_FILE);
			return x;
		}
		
		// check IP type and return IP number & index (if exists)
		auto ipdata = checkip(ipaddress);
		
		if (ipdata.iptype == 0) {
			x = loadmessage(MSG_INVALID_IP);
			return x;
		}
		
		uint colsize = 0;
		uint baseaddr = 0;
		uint low = 0;
		uint high = 0;
		uint mid = 0;
		uint rowoffset = 0;
		uint rowoffset2 = 0;
		uint countrypos = 0;
		BigInt ipno = ipdata.ipnum;
		BigInt ipfrom;
		BigInt ipto;
		BigInt maxip;
		
		if (ipdata.iptype == 4) {
			baseaddr = meta.ipv4databaseaddr;
			high = meta.ipv4databasecount;
			maxip = MAX_IPV4_RANGE;
			colsize = meta.ipv4columnsize;
		}
		else {
			if (meta.ipv6databasecount == 0) {
				x = loadmessage(MSG_IPV6_UNSUPPORTED);
				return x;
			}
			baseaddr = meta.ipv6databaseaddr;
			high = meta.ipv6databasecount;
			maxip = MAX_IPV6_RANGE;
			colsize = meta.ipv6columnsize;
		}
		
		// reading index
		if (ipdata.ipindex > 0) {
			low = readuint(ipdata.ipindex);
			high = readuint(ipdata.ipindex + 4);
		}
		
		if (ipno >= maxip) {
			ipno = ipno - 1;
		}
		
		while (low <= high) {
			mid = ((low + high) >> 1);
			rowoffset = baseaddr + (mid * colsize);
			rowoffset2 = rowoffset + colsize;
			
			if (ipdata.iptype == 4) {
				ipfrom = readuint(rowoffset);
				ipto = readuint(rowoffset2);
			}
			else {
				ipfrom = readuint128(rowoffset);
				ipto = readuint128(rowoffset2);
			}
			
			if ((ipno >= ipfrom) && (ipno < ipto)) {
				if (ipdata.iptype == 6) {
					rowoffset = rowoffset + 12; // coz below is assuming all columns are 4 bytes, so got 12 left to go to make 16 bytes total
				}
				
				if (proxytype_enabled) {
					if ((mode & PROXYTYPE) || (mode & ISPROXY)) {
						x.proxy_type = readstr(readuint(rowoffset + proxytype_position_offset));
					}
				}
				
				if (country_enabled) {
					if ((mode & COUNTRYSHORT) || (mode & COUNTRYLONG) || (mode & ISPROXY)) {
						countrypos = readuint(rowoffset + country_position_offset);
					}
					if ((mode & COUNTRYSHORT) || (mode & ISPROXY)) {
						x.country_short = readstr(countrypos);
					}
					if (mode & COUNTRYLONG) {
						x.country_long = readstr(countrypos + 3);
					}
				}
				
				if ((mode & REGION) && (region_enabled)) {
					x.region = readstr(readuint(rowoffset + region_position_offset));
				}
				
				if ((mode & CITY) && (city_enabled)) {
					x.city = readstr(readuint(rowoffset + city_position_offset));
				}
				
				if ((mode & ISP) && (isp_enabled)) {
					x.isp = readstr(readuint(rowoffset + isp_position_offset));
				}
				
				if ((x.country_short == "-") || (x.proxy_type == "-")) {
					x.is_proxy = 0;
				}
				else {
					if (x.proxy_type == "DCH") {
						x.is_proxy = 2;
					}
					else {
						x.is_proxy = 1;
					}
				}
				
				return x;
			}
			else {
				if (ipno < ipfrom) {
					high = mid - 1;
				}
				else {
					low = mid + 1;
				}
			}
		}
		
		return x;
	}
}
