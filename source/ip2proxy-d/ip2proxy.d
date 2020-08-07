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
	string domain = "-";
	string usage_type = "-";
	string asn = "-";
	string as = "-";
	string last_seen = "-";
	string threat = "-";
	byte is_proxy = -1;
}

protected struct ipv {
	uint iptype = 0;
	BigInt ipnum = BigInt("0");
	uint ipindex = 0; 
}

const ubyte[11] COUNTRY_POSITION = [0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3];
const ubyte[11] REGION_POSITION = [0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4];
const ubyte[11] CITY_POSITION = [0, 0, 0, 5, 5, 5, 5, 5, 5, 5, 5];
const ubyte[11] ISP_POSITION = [0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6];
const ubyte[11] PROXYTYPE_POSITION = [0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2];
const ubyte[11] DOMAIN_POSITION = [0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7];
const ubyte[11] USAGETYPE_POSITION = [0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8];
const ubyte[11] ASN_POSITION = [0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9];
const ubyte[11] AS_POSITION = [0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10];
const ubyte[11] LASTSEEN_POSITION = [0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11];
const ubyte[11] THREAT_POSITION = [0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12];

protected const string MODULE_VERSION = "3.0.0";

protected const BigInt MAX_IPV4_RANGE = BigInt("4294967295");
protected const BigInt MAX_IPV6_RANGE = BigInt("340282366920938463463374607431768211455");
protected const BigInt FROM_6TO4 = BigInt("42545680458834377588178886921629466624");
protected const BigInt TO_6TO4 = BigInt("42550872755692912415807417417958686719");
protected const BigInt FROM_TEREDO = BigInt("42540488161975842760550356425300246528");
protected const BigInt TO_TEREDO = BigInt("42540488241204005274814694018844196863");
protected const BigInt LAST_32BITS = BigInt("4294967295");

protected const uint COUNTRYSHORT = 0X00001;
protected const uint COUNTRYLONG = 0X00002;
protected const uint REGION = 0X00004;
protected const uint CITY = 0X00008;
protected const uint ISP = 0X00010;
protected const uint PROXYTYPE = 0X00020;
protected const uint ISPROXY = 0X00040;
protected const uint DOMAIN = 0X00080;
protected const uint USAGETYPE = 0X00100;
protected const uint ASN = 0X00200;
protected const uint AS = 0X00400;
protected const uint LASTSEEN = 0X00800;
protected const uint THREAT = 0X01000;

protected const uint ALL = COUNTRYSHORT | COUNTRYLONG | REGION | CITY | ISP | PROXYTYPE | ISPROXY | DOMAIN | USAGETYPE | ASN | AS | LASTSEEN | THREAT;

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
	private uint domain_position_offset;
	private uint usagetype_position_offset;
	private uint asn_position_offset;
	private uint as_position_offset;
	private uint lastseen_position_offset;
	private uint threat_position_offset;
	
	private bool country_enabled;
	private bool region_enabled;
	private bool city_enabled;
	private bool isp_enabled;
	private bool proxytype_enabled;
	private bool domain_enabled;
	private bool usagetype_enabled;
	private bool asn_enabled;
	private bool as_enabled;
	private bool lastseen_enabled;
	private bool threat_enabled;
	
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
		domain_position_offset = 0;
		usagetype_position_offset = 0;
		asn_position_offset = 0;
		as_position_offset = 0;
		lastseen_position_offset = 0;
		threat_position_offset = 0;
		country_enabled = false;
		region_enabled = false;
		city_enabled = false;
		isp_enabled = false;
		proxytype_enabled = false;
		domain_enabled = false;
		usagetype_enabled = false;
		asn_enabled = false;
		as_enabled = false;
		lastseen_enabled = false;
		threat_enabled = false;
		
		destroy(db);
		
		return 0;
	}
	
	// read string
	private string readstr(uint index) {
		uint pos = index + 1;
		ubyte len = cast(ubyte)db[index]; // get length of string
		char[] stuff = cast(char[])db[pos .. (pos + len)];
		return to!string(stuff);
	}
	
	// read unsigned 32-bit integer from row
	private uint readuint_row(ref ubyte[] row, uint index) {
		ubyte[4] buf = row[index .. (index + 4)];
		uint result = 0;
		result = littleEndianToNative!uint(buf);
		return result;
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
	
	// read float from row
	private float readfloat_row(ref ubyte[] row, uint index) {
		ubyte[4] buf = row[index .. (index + 4)];
		float result = 0.0;
		result = littleEndianToNative!float(buf);
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
			// country_position_offset = (COUNTRY_POSITION[dbt] != 0) ? (COUNTRY_POSITION[dbt] - 1) << 2 : 0;
			// region_position_offset = (REGION_POSITION[dbt] != 0) ? (REGION_POSITION[dbt] - 1) << 2 : 0;
			// city_position_offset = (CITY_POSITION[dbt] != 0) ? (CITY_POSITION[dbt] - 1) << 2 : 0;
			// isp_position_offset = (ISP_POSITION[dbt] != 0) ? (ISP_POSITION[dbt] - 1) << 2 : 0;
			// proxytype_position_offset = (PROXYTYPE_POSITION[dbt] != 0) ? (PROXYTYPE_POSITION[dbt] - 1) << 2 : 0;
			// domain_position_offset = (DOMAIN_POSITION[dbt] != 0) ? (DOMAIN_POSITION[dbt] - 1) << 2 : 0;
			// usagetype_position_offset = (USAGETYPE_POSITION[dbt] != 0) ? (USAGETYPE_POSITION[dbt] - 1) << 2 : 0;
			// asn_position_offset = (ASN_POSITION[dbt] != 0) ? (ASN_POSITION[dbt] - 1) << 2 : 0;
			// as_position_offset = (AS_POSITION[dbt] != 0) ? (AS_POSITION[dbt] - 1) << 2 : 0;
			// lastseen_position_offset = (LASTSEEN_POSITION[dbt] != 0) ? (LASTSEEN_POSITION[dbt] - 1) << 2 : 0;
			// threat_position_offset = (THREAT_POSITION[dbt] != 0) ? (THREAT_POSITION[dbt] - 1) << 2 : 0;
			
			// offset slightly different when reading by row
			country_position_offset = (COUNTRY_POSITION[dbt] != 0) ? (COUNTRY_POSITION[dbt] - 2) << 2 : 0;
			region_position_offset = (REGION_POSITION[dbt] != 0) ? (REGION_POSITION[dbt] - 2) << 2 : 0;
			city_position_offset = (CITY_POSITION[dbt] != 0) ? (CITY_POSITION[dbt] - 2) << 2 : 0;
			isp_position_offset = (ISP_POSITION[dbt] != 0) ? (ISP_POSITION[dbt] - 2) << 2 : 0;
			proxytype_position_offset = (PROXYTYPE_POSITION[dbt] != 0) ? (PROXYTYPE_POSITION[dbt] - 2) << 2 : 0;
			domain_position_offset = (DOMAIN_POSITION[dbt] != 0) ? (DOMAIN_POSITION[dbt] - 2) << 2 : 0;
			usagetype_position_offset = (USAGETYPE_POSITION[dbt] != 0) ? (USAGETYPE_POSITION[dbt] - 2) << 2 : 0;
			asn_position_offset = (ASN_POSITION[dbt] != 0) ? (ASN_POSITION[dbt] - 2) << 2 : 0;
			as_position_offset = (AS_POSITION[dbt] != 0) ? (AS_POSITION[dbt] - 2) << 2 : 0;
			lastseen_position_offset = (LASTSEEN_POSITION[dbt] != 0) ? (LASTSEEN_POSITION[dbt] - 2) << 2 : 0;
			threat_position_offset = (THREAT_POSITION[dbt] != 0) ? (THREAT_POSITION[dbt] - 2) << 2 : 0;
			
			country_enabled = (COUNTRY_POSITION[dbt] != 0) ? true : false;
			region_enabled = (REGION_POSITION[dbt] != 0) ? true : false;
			city_enabled = (CITY_POSITION[dbt] != 0) ? true : false;
			isp_enabled = (ISP_POSITION[dbt] != 0) ? true : false;
			proxytype_enabled = (PROXYTYPE_POSITION[dbt] != 0) ? true : false;
			domain_enabled = (DOMAIN_POSITION[dbt] != 0) ? true : false;
			usagetype_enabled = (USAGETYPE_POSITION[dbt] != 0) ? true : false;
			asn_enabled = (ASN_POSITION[dbt] != 0) ? true : false;
			as_enabled = (AS_POSITION[dbt] != 0) ? true : false;
			lastseen_enabled = (LASTSEEN_POSITION[dbt] != 0) ? true : false;
			threat_enabled = (THREAT_POSITION[dbt] != 0) ? true : false;
			
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
				else if (ipdata.ipnum >= FROM_6TO4 && ipdata.ipnum <= TO_6TO4) {
					// 6to4 so need to remap to ipv4
					ipdata.iptype = 4;
					ipdata.ipnum = ipdata.ipnum >> 80;
					ipdata.ipnum = ipdata.ipnum & LAST_32BITS;
					uint ipno2 = to!uint(ipdata.ipnum);
					if (meta.ipv4indexbaseaddr > 0) {
						ipdata.ipindex = ((ipno2 >> 16) << 3) + meta.ipv4indexbaseaddr;
					}
				}
				else if (ipdata.ipnum >= FROM_TEREDO && ipdata.ipnum <= TO_TEREDO) {
					// Teredo so need to remap to ipv4
					ipdata.iptype = 4;
					ipdata.ipnum = ~ipdata.ipnum; // bitwise NOT
					ipdata.ipnum = ipdata.ipnum & LAST_32BITS;
					uint ipno2 = to!uint(ipdata.ipnum);
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
		x["Domain"] = data.domain;
		x["UsageType"] = data.usage_type;
		x["ASN"] = data.asn;
		x["AS"] = data.as;
		x["LastSeen"] = data.last_seen;
		x["Threat"] = data.threat;
		
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
	
	// get domain
	public auto get_domain(const string ipaddress) {
		auto data = query(ipaddress, DOMAIN);
		return data.domain;
	}
	
	// get usage type
	public auto get_usage_type(const string ipaddress) {
		auto data = query(ipaddress, USAGETYPE);
		return data.usage_type;
	}
	
	// get asn
	public auto get_asn(const string ipaddress) {
		auto data = query(ipaddress, ASN);
		return data.asn;
	}
	
	// get as
	public auto get_as(const string ipaddress) {
		auto data = query(ipaddress, AS);
		return data.as;
	}
	
	// get last seen
	public auto get_last_seen(const string ipaddress) {
		auto data = query(ipaddress, LASTSEEN);
		return data.last_seen;
	}
	
	// get threat
	public auto get_threat(const string ipaddress) {
		auto data = query(ipaddress, THREAT);
		return data.threat;
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
				uint firstcol = 4; // 4 bytes for ip from
				if (ipdata.iptype == 6) {
					firstcol = 16; // 16 bytes for ipv6
					// rowoffset = rowoffset + 12; // coz below is assuming all columns are 4 bytes, so got 12 left to go to make 16 bytes total
				}
				ubyte[] row = cast(ubyte[])db[(rowoffset + firstcol - 1) .. (rowoffset + colsize - 1)];
				
				if (proxytype_enabled) {
					if ((mode & PROXYTYPE) || (mode & ISPROXY)) {
						// x.proxy_type = readstr(readuint(rowoffset + proxytype_position_offset));
						x.proxy_type = readstr(readuint_row(row, proxytype_position_offset));
					}
				}
				
				if (country_enabled) {
					if ((mode & COUNTRYSHORT) || (mode & COUNTRYLONG) || (mode & ISPROXY)) {
						// countrypos = readuint(rowoffset + country_position_offset);
						countrypos = readuint_row(row, country_position_offset);
					}
					if ((mode & COUNTRYSHORT) || (mode & ISPROXY)) {
						x.country_short = readstr(countrypos);
					}
					if (mode & COUNTRYLONG) {
						x.country_long = readstr(countrypos + 3);
					}
				}
				
				if ((mode & REGION) && (region_enabled)) {
					// x.region = readstr(readuint(rowoffset + region_position_offset));
					x.region = readstr(readuint_row(row, region_position_offset));
				}
				
				if ((mode & CITY) && (city_enabled)) {
					// x.city = readstr(readuint(rowoffset + city_position_offset));
					x.city = readstr(readuint_row(row, city_position_offset));
				}
				
				if ((mode & ISP) && (isp_enabled)) {
					// x.isp = readstr(readuint(rowoffset + isp_position_offset));
					x.isp = readstr(readuint_row(row, isp_position_offset));
				}
				
				if ((mode & DOMAIN) && (domain_enabled)) {
					// x.domain = readstr(readuint(rowoffset + domain_position_offset));
					x.domain = readstr(readuint_row(row, domain_position_offset));
				}
				
				if ((mode & USAGETYPE) && (usagetype_enabled)) {
					// x.usage_type = readstr(readuint(rowoffset + usagetype_position_offset));
					x.usage_type = readstr(readuint_row(row, usagetype_position_offset));
				}
				
				if ((mode & ASN) && (asn_enabled)) {
					// x.asn = readstr(readuint(rowoffset + asn_position_offset));
					x.asn = readstr(readuint_row(row, asn_position_offset));
				}
				
				if ((mode & AS) && (as_enabled)) {
					// x.as = readstr(readuint(rowoffset + as_position_offset));
					x.as = readstr(readuint_row(row, as_position_offset));
				}
				
				if ((mode & LASTSEEN) && (lastseen_enabled)) {
					// x.last_seen = readstr(readuint(rowoffset + lastseen_position_offset));
					x.last_seen = readstr(readuint_row(row, lastseen_position_offset));
				}
				
				if ((mode & THREAT) && (threat_enabled)) {
					// x.threat = readstr(readuint(rowoffset + threat_position_offset));
					x.threat = readstr(readuint_row(row, threat_position_offset));
				}
				
				if ((x.country_short == "-") || (x.proxy_type == "-")) {
					x.is_proxy = 0;
				}
				else {
					if ((x.proxy_type == "DCH") || (x.proxy_type == "SES")) {
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
