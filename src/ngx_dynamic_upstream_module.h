/*
 * Copyright (c) 2015 Tatsuhiko Kubo (cubicdaiya@gmail.com>)
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

#ifndef NGX_DYNAMIC_UPSTREAM_H
#define NGX_DYNAMIC_UPSTREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_stream.h>

#ifdef __cplusplus
}
#endif


#define NGX_DYNAMIC_UPSTEAM_OP_LIST   1
#define NGX_DYNAMIC_UPSTEAM_OP_ADD    2
#define NGX_DYNAMIC_UPSTEAM_OP_REMOVE 4
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM  8
#define NGX_DYNAMIC_UPSTEAM_OP_SYNC   16

#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT       1
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS    2
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT 4
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP           8
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN         16

#if defined(nginx_version) && (nginx_version >= 1011005)
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS    32
#endif

#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE       64
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE_SYNC  128
#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6          256

#define NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM        1024

typedef struct ngx_dynamic_upstream_op_t {
    ngx_int_t   verbose;
    ngx_int_t   op;
    ngx_int_t   op_param;

    ngx_int_t   backup;
    ngx_int_t   weight;
    ngx_int_t   max_fails;

#if defined(nginx_version) && (nginx_version >= 1011005)
    ngx_int_t   max_conns;
#endif

    ngx_int_t   fail_timeout;
    ngx_int_t   up;
    ngx_int_t   down;
    ngx_str_t   upstream;
    ngx_str_t   server;

    ngx_int_t   no_lock;

    ngx_uint_t  status;
    const char *err;

    ngx_uint_t  hash;
} ngx_dynamic_upstream_op_t;

#ifdef __cplusplus
extern "C" {
#endif

ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_http_upstream_srv_conf_t *uscf);


ngx_int_t
ngx_dynamic_upstream_stream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_stream_upstream_srv_conf_t *uscf);

#ifdef __cplusplus
}
#endif

#endif /* NGX_DYNAMIC_UPSTEAM_H */
