use lib 'lib';
use Test::Nginx::Socket;
use Test::Nginx::Socket::Lua::Stream;

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: list
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
    GET /dynamic?upstream=backends&stream=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;


=== TEST 2: list verbose
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
    GET /dynamic?upstream=backends&verbose=&stream=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6002 addr=127.0.0.1:6002 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;
server 127.0.0.1:6003 addr=127.0.0.1:6003 weight=1 max_fails=1 fail_timeout=10 max_conns=0 conns=0;


=== TEST 3: not found upstream
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
    GET /dynamic?upstream=not_found&stream=
--- response_body_like: upstream is not found
--- error_code: 404
