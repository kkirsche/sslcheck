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

```
~/g/s/g/k/urltrace git:master ❯❯❯ sslcheck www.google.com
Checking Host: www.google.com.
Checking for version: TLS1.2.
Version supported: TLS1.2.
Checking for version: TLS1.1.
Version supported: TLS1.1.
Checking for version: TLS1.0.
Version supported: TLS1.0.
Checking for version: SSLv3.
tls: server selected unsupported protocol version 300
```

```
~/g/g/s/g/k/sslcheck ❯❯❯ sslcheck --verbose www.google.com
Checking Host: www.google.com.
Checking for version: TLS1.2.
Version supported: TLS1.2.
Server key information:
	Common Name:	 www.google.com
	Organizational Unit:	 []
	Organization:	 [Google Inc]
	City:	 [Mountain View]
	State:	 [California]
	Country: [US]
SSL Certificate Valid:
	From:	 2016-06-01 10:20:48 +0000 UTC
	To:	 2016-08-24 10:11:00 +0000 UTC
Valid Certificate Domain Names:
	www.google.com
Issued by:
	Google Internet Authority G2
	[]
	[Google Inc]
Checking for version: TLS1.1.
Version supported: TLS1.1.
Checking for version: TLS1.0.
Version supported: TLS1.0.
Checking for version: SSLv3.
tls: server selected unsupported protocol version 300
```
