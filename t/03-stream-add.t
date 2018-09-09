use lib 'lib';
use Test::Nginx::Socket;
use Test::Nginx::Socket::Lua::Stream;

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: add
--- stream_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- stream_server_config
    proxy_pass backends;
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=localhost:6004&add=&stream=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
server localhost:6004 addr=127.0.0.1:6004;


=== TEST 2: add and update parameters
--- stream_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- stream_server_config
    proxy_pass backends;
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=&weight=10&stream=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6002 addr=127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6003 addr=127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6004 addr=127.0.0.1:6004 weight=10 max_fails=1 fail_timeout=10 max_conns=0 conns=0;


=== TEST 3: add duplicated server
--- stream_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- stream_server_config
    proxy_pass backends;
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6003&add=&stream=
--- response_body_like:
--- error_code: 304


=== TEST 4: add and remove
--- stream_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- stream_server_config
    proxy_pass backends;
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=&remove=&stream=
--- response_body_like: add, sync and remove at once are not allowed
--- error_code: 400

=== TEST 5: add backup
--- stream_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003;
    }
--- stream_server_config
    proxy_pass backends;
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&add=&backup=&stream=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;
server 127.0.0.1:6004 addr=127.0.0.1:6004 backup;
