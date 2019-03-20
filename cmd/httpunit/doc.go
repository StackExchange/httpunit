/*

httpunit tests compliance of web and net servers with desired output.

It has three modes. All modes support flag options. The toml and hiera modes
may be used together.

If toml is specified, that toml file is read into the configuration. See
the TOML section below for format.

If hiera is specified, the listeners from it are extracted and tested.

If url is specified, it checks only the specified URL with optional IP
address, status code, and regex. If url does not contain a scheme ("https://",
"http://"), "http://" is prefixed. The IP may be an empty string to indicate
all IP addresses resolved to from the URL's hostname.

Usage:
	httpunit [flag] [-hiera="path/to/sets.json"] [-toml="/path/to/httpunit.toml"] [url] [ip] [code] [regex]

The flags are:
	-filter=""
		if specified, only uses this IP address; may end with "." to
		filter by IPs that start with the filter
	-no10=false
		no RFC1918 addresses
	-timeout="3s"
		connection timeout
	-tags=""
	    if specified, only runs plans that are tagged with one of the
		tags specified. You can specify more than one tag, seperated by commas
	-protos=""
		if specified, only runs plans where the URL contains the given
		protocol. Valid protocols are: http,https,tcp,tcp4,tcp6,udp,udp4,udp6,ip,ip4,ip6
		You can specify more than one protocol, seperated by commas
	-header="X-Request-Guid"
		in more verbose mode, print this HTTP header
	-v
		verbose output:show successes
	-vv
		more verbose output: show -header, cert details

URLs

URLs may be specified with various protocols: http, https, tcp,
udp, ip. "4" or "6" may be appended to tcp, udp, and ip (as per
http://golang.org/pkg/net/#Dial). tcp and udp must specify a port, or default
to 0. http and https may specify a port to override the default.

TOML

The toml file (https://github.com/toml-lang/toml) has two sections: IPs,
a table of search and replace regexes, and Plan, an array of tables listing
test plans.

The IPs table has keys as regexes and values as lists of replacements. A
"*" specifies to perform DNS resolution. If an address contains something
of the form "(x+y)", it is replaced with the sum of x and y.

The plan table array can specify the label, url and ips (array of
string). text, code (number), and regex may be specified for http[s] URLs
to require matching returns. code defaults to 200.

An example file:

	[IPs]
	  BASEIP = ["87.65.43."]
	  '^(\d+)$' = ["*", "BASEIP$1", "BASEIP($1+64)", "1.2.3.$1"]
	  '^(\d+)INT$' = ["*", "10.0.1.$1", "10.0.2.$1", "BASEIP$1", "BASEIP($1+64)"]

	[[plan]]
	  label = "api"
	  url = "http://api.example.com/"
	  ips = ["16", "8.7.6.5"]
	  text = "API for example.com"
	  regex = "some regex"

	[[plan]]
	  label = "redirect"
	  url = "https://example.com/redirect"
	  ips = ["*", "20INT"]
	  code = 301

	[[plan]]
	  label = "mail"
	  url = "tcp://mail-host.com:25"

	[[plan]]
	  label = "self-signed"
	  url = "https://internal.example.com"
	  insecureSkipVerify = true
	  code = 200
*/
package main
