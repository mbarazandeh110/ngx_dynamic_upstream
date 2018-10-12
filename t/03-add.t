use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: add
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
server 127.0.0.1:6004 addr=127.0.0.1:6004;


=== TEST 2: add and update parameters
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=&weight=10
--- response_body_like
server 127.0.0.1:6001 addr=127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6002 addr=127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6003 addr=127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6004 addr=127.0.0.1:6004 weight=10 max_fails=1 fail_timeout=10 max_conns=0 conns=0;


=== TEST 3: add duplicated server
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6003&add=
--- response_body_like:
--- error_code: 304


=== TEST 4: add and remove
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=&remove=
--- response_body_like: add and remove at once are not allowed
--- error_code: 400


=== TEST 5: add backup
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=&backup=
--- response_body_like
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
server 127.0.0.1:6004 addr=127.0.0.1:6004 backup;


=== TEST 6: add bad request
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=localhost:6004&add=
--- response_body_like: domain names are supported only for upstreams
--- error_code: 400


=== TEST 7: add and remove dns resolve
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        dns_update 0s;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
    location /test {
       content_by_lua_block {
          local resp = assert(ngx.location.capture("/dynamic?upstream=backends&server=localhost:6004&add="))
          ngx.say(resp.body)
          ngx.sleep(1.2)
          resp = assert(ngx.location.capture("/dynamic?upstream=backends"))
          ngx.print(resp.body)
          resp = assert(ngx.location.capture("/dynamic?upstream=backends&remove=&server=localhost:6004"))
          ngx.print(resp.body)
          resp = assert(ngx.location.capture("/dynamic?upstream=backends&server=localhost:6004&add=&backup="))
          ngx.say(resp.body)
          ngx.sleep(1.2)
          resp = assert(ngx.location.capture("/dynamic?upstream=backends"))
          ngx.print(resp.body)
          resp = assert(ngx.location.capture("/dynamic?upstream=backends&remove=&server=localhost:6004"))
          ngx.print(resp.body)
       }
    }
--- request
    GET /test
--- response_body_like
DNS resolving in progress
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
server localhost:6004 addr=127.0.0.1:6004;
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
DNS resolving in progress
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
server localhost:6004 addr=127.0.0.1:6004 backup;
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
