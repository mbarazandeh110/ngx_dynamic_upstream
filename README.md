# ngx_dynamic_upstream

`ngx_dynamic_upstream` is the module for operating upstreams dynamically with HTTP APIs
such as [`ngx_http_upstream_conf`](http://nginx.org/en/docs/http/ngx_http_upstream_conf_module.html).

This module also supports stream upstreams manipulation.

Online reconfiguration upstream addresses from DNS by hostname without reloads.

# Build status
[![Build Status](https://travis-ci.org/ZigzagAK/ngx_dynamic_upstream.svg)](https://travis-ci.org/ZigzagAK/ngx_dynamic_upstream)

# Requirements

`ngx_dynamic_upstream` requires the `zone` directive in the `upstream` context.

# Status

Production ready.

# Directives

## dynamic_upstream

|Syntax |dynamic_upstream|
|-------|----------------|
|Default|-|
|Context|location|

## dns_update

|Syntax |dns_update 60s|
|-------|----------------|
|Default|-|
|Context|upstream|

Background synchronization hosts addresses by DNS.

## dns_add_down

|Syntax |dns_add_down on/off|
|-------|----------------|
|Default|off|
|Context|upstream|

Add new peers in down state.

## dns_ipv6

|Syntax |dns_ipv6 on|
|-------|----------------|
|Default|-|
|Context|upstream|

Include IPv6 addresses.

# Quick Start

```nginx

http {
    upstream backends {
        zone zone_for_backends 1m;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }

    server {
        listen 6000;

        location /dynamic {
            allow 127.0.0.1;
            deny all;
            dynamic_upstream;
        }

        location / {
            proxy_pass http://backends;
        }
    }
}

stream {
    upstream backends_stream {
        zone zone_for_backends_stream 1m;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }

    server {
        listen 6001;
        proxy_pass backends_stream;
    }
}
```

## DNS background updates

```nginx
http {
    upstream mail {
        zone mail 1m;
        dns_update 60s;
        dns_ipv6 off;
        server mail.ru;
        server google.com backup;
    }

    server {
        listen 6000;

        location /dynamic {
            allow 127.0.0.1;
            deny all;
            dynamic_upstream;
        }

        location / {
            proxy_pass http://backends;
        }
    }
}
```

# HTTP APIs

You can operate upstreams dynamically with HTTP APIs.

## list

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=mail"
server mail.ru addr=217.69.139.201:80;
server mail.ru addr=94.100.180.201:80;
server mail.ru addr=217.69.139.200:80;
server mail.ru addr=94.100.180.200:80;
server google.com addr=173.194.73.139:80 backup;
server google.com addr=173.194.73.100:80 backup;
server google.com addr=173.194.73.101:80 backup;
server google.com addr=173.194.73.138:80 backup;
server google.com addr=173.194.73.102:80 backup;
server google.com addr=173.194.73.113:80 backup;
$
```

## verbose

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=mail&verbose="
server mail.ru addr=94.100.180.200:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server mail.ru addr=94.100.180.201:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server mail.ru addr=217.69.139.200:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server mail.ru addr=217.69.139.201:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server google.com addr=64.233.165.101:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 backup;
server google.com addr=64.233.165.102:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 backup;
server google.com addr=64.233.165.139:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 backup;
server google.com addr=64.233.165.138:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 backup;
server google.com addr=64.233.165.100:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 backup;
server google.com addr=64.233.165.113:80 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 backup;
$
```

## update_parameters

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&server=127.0.0.1:6003&weight=10&max_fails=5&fail_timeout=5&max_conns=10"
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6003 weight=10 max_fails=5 fail_timeout=5 max_conns=10 conns=0;
$
```

The supported parameters are below.

 * weight
 * max_fails
 * fail_timeout

## down

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&server=127.0.0.1:6003&down="
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0 down;
$
```

## up

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&server=127.0.0.1:6003&up="
server 127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
$
```

## add peer

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&add=&server=127.0.0.1:6004"
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6003;
server 127.0.0.1:6004;
$
```

## add host
```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&add=&server=localhost:6004"
DNS resolving in progress
$
```
Peers will be added in background.

## add backup peer

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&add=&server=127.0.0.1:6004&backup="
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6003;
server 127.0.0.1:6004 backup;
$
```

## remove peer

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&remove=&server=127.0.0.1:6003"
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6004;
$
```

## remove server

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends&remove=&server=mail.ru"
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6004;
$
```

## add stream

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends_stream&add=&server=127.0.0.1:6004&stream="
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6003;
server 127.0.0.1:6004;
$
```

## add backup stream

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends_stream&add=&server=127.0.0.1:6004&backup=&stream="
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6003;
server 127.0.0.1:6004 backup;
$
```

## remove stream

```bash
$ curl "http://127.0.0.1:6000/dynamic?upstream=backends_stream&remove=&server=127.0.0.1:6003&stream="
server 127.0.0.1:6001;
server 127.0.0.1:6002;
server 127.0.0.1:6004;
$
```

# License

See [LICENSE](https://github.com/cubicdaiya/ngx_dynamic_upstream/blob/master/LICENSE).
