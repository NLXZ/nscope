# nscope

A fast tool for filtering URLs and domains based on bug bounty scope.

## Installation

```sh
go install github.com/nlxz/nscope@latest
```

## Usage

```
Usage:
  nscope [flags]

Flags:
  -l string     file containing list of urls/domains (if empty read from stdin)
  -s string     file containing scope domains (required)
  -r            print lines that do not match scope
```

```
$ cat scope.txt
example.com
*.test.com
staging.*.domain.com

$ cat urls.txt
https://example.com
http://example.com:8080
ftp://files.example.com
https://example.com/path/to/page?query=string
example.com
test.com
sub.test.com
domain.com:80
http://domain.com:80
deep.nested.sub.test.com
https://example.com/login [200]
staging.eu.domain.com
staging.domain.com
production.eu.domain.com
external-site.com
api.other-service.net
dev.internal.net
example.com.
EXAMPLE.COM
Http://Example.Com:80/path

$ nscope -s scope.txt -l urls.txt
https://example.com
http://example.com:8080
https://example.com/path/to/page?query=string
example.com
test.com
sub.test.com
deep.nested.sub.test.com
https://example.com/login [200]
staging.eu.domain.com
example.com.
EXAMPLE.COM
Http://Example.Com:80/path

$ nscope -s scope.txt -l urls.txt -r
ftp://files.example.com
domain.com:80
http://domain.com:80
staging.domain.com
production.eu.domain.com
external-site.com
api.other-service.net
dev.internal.net
```