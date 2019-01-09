use lib 'lib';
use Test::Nginx::Socket;

plan tests => repeat_each() * 2 * blocks();

run_tests();

__DATA__

=== TEST 1: remove head
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
    GET /dynamic?upstream=backends&server=127.0.0.1:6001&remove=
--- response_body
server 127.0.0.1:6002 addr=127.0.0.1:6002;
server 127.0.0.1:6003 addr=127.0.0.1:6003;


=== TEST 2: remove tail
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
    GET /dynamic?upstream=backends&server=127.0.0.1:6003&remove=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;


=== TEST 3: remove middle
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
    GET /dynamic?upstream=backends&server=127.0.0.1:6002&remove=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6003 addr=127.0.0.1:6003;


=== TEST 4: fail to remove
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
    GET /dynamic?upstream=backends&server=127.0.0.1:6004&remove=
--- response_body_like:
--- error_code: 304


=== TEST 5: remove backup
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
        server 127.0.0.1:6002;
        server 127.0.0.1:6003 backup;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6003&remove=
--- response_body
server 127.0.0.1:6001 addr=127.0.0.1:6001;
server 127.0.0.1:6002 addr=127.0.0.1:6002;


=== TEST 6: remove single
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 127.0.0.1:6001;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=127.0.0.1:6001&remove=
--- response_body
server 0.0.0.0:1 addr=0.0.0.0:1 down;


=== TEST 7: remove single 0.0.0.0:1
--- http_config
    upstream backends {
        zone zone_for_backends 128k;
        server 0.0.0.0:1;
    }
--- config
    location /dynamic {
        dynamic_upstream;
    }
--- request
    GET /dynamic?upstream=backends&server=0.0.0.0:1&remove=
--- error_code: 304
--- response_body
server 0.0.0.0:1 addr=0.0.0.0:1;
