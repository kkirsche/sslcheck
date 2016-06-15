# sslcheck
Report versions of SSL/TLS which are supported by a remote host or hosts

## Installation

You may use the pre compiled binaries in /bin or:

```
go get -u -v github.com/kkirsche/sslcheck
```

## Usage

```
sslcheck www.google.com

sslcheck -p 443 www.google.com

sslcheck --port 443 www.google.com

sslcheck -t 10 www.google.com

sslcheck --timeout 10 www.google.com

sslcheck -v www.google.com

sslcheck --verbose www.google.com
```

## Example

Normal mode:
```
~/g/g/s/g/k/sslcheck ❯❯❯ sslcheck www.google.com
Checking Host: www.google.com.
Checking for version: TLS1.2
Checking for version: TLS1.1
Checking for version: TLS1.0
Checking for version: SSLv3
[TLS Handshake] SSLv3 — tls: server selected unsupported protocol version 300 (www.google.com)
[Supported SSL Versions] SSLv3: false, TLS1.0: true, TLS1.1: true, TLS1.2: true
```

Verbose mode:
```
~/g/g/s/g/k/sslcheck ❯❯❯ sslcheck --verbose www.google.com
Checking Host: www.google.com.
Checking for version: TLS1.2
Server key information:
	Common Name:	 www.google.com
	Organizational Unit:
	Organization:	Google Inc
	City:	Mountain View
	State:	California
	Country:US

SSL Certificate Valid:
	From:	 2016-06-08 12:37:29 +0000 UTC
	To:	 2016-08-31 12:30:00 +0000 UTC

Valid Certificate Domain Names:
	www.google.com
Issued by:
	Google Internet Authority G2

Google Inc
Checking for version: TLS1.1
Checking for version: TLS1.0
Checking for version: SSLv3
[TLS Handshake] SSLv3 — tls: server selected unsupported protocol version 300 (www.google.com)
[Supported SSL Versions] SSLv3: false, TLS1.0: true, TLS1.1: true, TLS1.2: true
```
