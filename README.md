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

sslcheck --port 443 www.google.com/mail
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
