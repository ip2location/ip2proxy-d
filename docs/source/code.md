# IP2Proxy D API

## IP2Proxy Class
```{py:class} IP2Proxy(binpath)
Construct the IP2Location Class. Load the IP2Proxy BIN database for lookup.

:param str binPath: (Required) The file path links to IP2Proxy BIN databases.
```

```{py:function} package_version()
Return the database's type, 1 to 12 respectively for PX1 to PX12. Please visit https://www.ip2location.com/databases/ip2proxy for details.

:return: Returns the package version.
:rtype: string
```

```{py:function} module_version()
Return the version of module.

:return: Returns the module version.
:rtype: string
```

```{py:function} database_version()
Return the database's compilation date as a string of the form 'YYYY-MM-DD'.

:return: Returns the database version.
:rtype: string
```

```{py:function} close()
Closes BIN file and resets metadata.
```

```{py:function} get_all(ipaddress)
Retrieve geolocation information for an IP address.

:param string ipaddress: (Required) The IP address (IPv4 or IPv6).
:return: Returns the geolocation information in array. Refer below table for the fields avaliable in the array
:rtype: array

**RETURN FIELDS**

| Field Name       | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| CountryShort    |     Two-character country code based on ISO 3166. |
| CountryLong    |     Country name based on ISO 3166. |
| Region     |     Region or state name. |
| City       |     City name. |
| ISP            |     Internet Service Provider or company\'s name. |
| Domain         |     Internet domain name associated with IP address range. |
| UsageType      |     Usage type classification of ISP or company. |
| ASN            |     Autonomous system number (ASN). |
| AS             |     Autonomous system (AS) name. |
| LastSeen       |     Proxy last seen in days. |
| Threat         |     Security threat reported. |
| ProxyType      |     Type of proxy. |
| Provider       |     Name of VPN provider if available. |
| FraudScore       |     Potential risk score (0 - 99) associated with IP address. |
```