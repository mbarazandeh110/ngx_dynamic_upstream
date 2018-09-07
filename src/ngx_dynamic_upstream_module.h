#ifndef NGX_DYNAMIC_UPSTREAM_H
#define NGX_DYNAMIC_UPSTREAM_H


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_stream.h>


#define NGX_DYNAMIC_UPSTEAM_OP_LIST   0
#define NGX_DYNAMIC_UPSTEAM_OP_ADD    1
#define NGX_DYNAMIC_UPSTEAM_OP_REMOVE 2
#define NGX_DYNAMIC_UPSTEAM_OP_BACKUP 4
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM  8


#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT       1
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS    2
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT 4
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP           8
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN         16

#if defined(nginx_version) && (nginx_version >= 1011005)
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS    32
#endif

#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE      64
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6         128

#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM       256

typedef struct ngx_dynamic_upstream_op_t {
    ngx_int_t verbose;
    ngx_int_t op;
    ngx_int_t op_param;
    ngx_int_t backup;
    ngx_int_t weight;
    ngx_int_t max_fails;

#if defined(nginx_version) && (nginx_version >= 1011005)
    ngx_int_t max_conns;
#endif

    ngx_int_t fail_timeout;
    ngx_int_t up;
    ngx_int_t down;
    ngx_str_t upstream;
    ngx_str_t server;
    ngx_uint_t status;
} ngx_dynamic_upstream_op_t;


ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op, ngx_http_upstream_srv_conf_t *uscf);


ngx_int_t
ngx_dynamic_upstream_stream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op, ngx_stream_upstream_srv_conf_t *uscf);


#endif /* NGX_DYNAMIC_UPSTEAM_H */
