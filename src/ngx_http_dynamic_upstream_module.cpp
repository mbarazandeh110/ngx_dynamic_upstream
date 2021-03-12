/*
 * Copyright (c) 2015 Tatsuhiko Kubo (cubicdaiya@gmail.com>)
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

extern "C" {

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_stream.h>
#include <pthread.h>
#include <errno.h>

}


#ifndef NGX_THREADS

#include <new>

#endif


#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"


#undef  NGX_CONF_ERROR
#define NGX_CONF_ERROR (char *) -1


static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_int_t
ngx_http_dynamic_upstream_init_worker(ngx_cycle_t *cycle);

#ifndef NGX_THREADS

static void
ngx_http_dynamic_upstream_exit_worker(ngx_cycle_t *);

#endif

static void *
ngx_dynamic_upstream_create_srv_conf(ngx_conf_t *cf);


static char *
ngx_create_servers_file(ngx_conf_t *cf, void *post, void *data);

static char *
ngx_dynamic_upstream_dns_update(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

typedef struct {
    ngx_msec_t  interval;
    ngx_msec_t  next;
    ngx_uint_t  hash;
    ngx_flag_t  ipv6;
    ngx_flag_t  add_down;
    ngx_str_t   file;
#if (NGX_THREADS)
    volatile ngx_flag_t   busy;
    ngx_thread_pool_t    *thread_pool;
#endif
} ngx_dynamic_upstream_srv_conf_t;

static char *
ngx_create_servers_file(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_servers_file_post = {
    ngx_create_servers_file
};

static ngx_conf_num_bounds_t  ngx_check_update = {
    ngx_conf_check_num_bounds,
    500, 3600000
};

static ngx_command_t ngx_http_dynamic_upstream_commands[] = {

    { ngx_string("dynamic_upstream"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dynamic_upstream,
      0,
      0,
      NULL },

    { ngx_string("dns_update"),
      NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12,
      ngx_dynamic_upstream_dns_update,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, interval),
      &ngx_check_update },

    { ngx_string("dns_add_down"),
      NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, add_down),
      NULL },

    { ngx_string("dns_ipv6"),
      NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, ipv6),
      NULL },

    { ngx_string("dynamic_state_file"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, file),
      &ngx_servers_file_post },

    ngx_null_command
};


static ngx_command_t ngx_stream_dynamic_upstream_commands[] = {

    { ngx_string("dns_update"),
      NGX_STREAM_UPS_CONF | NGX_CONF_TAKE12,
      ngx_dynamic_upstream_dns_update,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, interval),
      &ngx_check_update },

    { ngx_string("dns_add_down"),
      NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, add_down),
      NULL },

    { ngx_string("dns_ipv6"),
      NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, ipv6),
      NULL },

    { ngx_string("dynamic_state_file"),
      NGX_STREAM_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_dynamic_upstream_srv_conf_t, file),
      &ngx_servers_file_post },

    ngx_null_command
};


static ngx_http_module_t ngx_http_dynamic_upstream_module_ctx = {
    NULL,                                       /* preconfiguration  */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main       */
    NULL,                                       /* init main         */

    ngx_dynamic_upstream_create_srv_conf,       /* create server     */
    NULL,                                       /* merge server      */

    NULL,                                       /* create location   */
    NULL                                        /* merge location    */
};


static ngx_stream_module_t ngx_stream_dynamic_upstream_module_ctx = {
    NULL,                                       /* preconfiguration  */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main       */
    NULL,                                       /* init main         */

    ngx_dynamic_upstream_create_srv_conf,       /* create server     */
    NULL                                        /* merge server      */
};


ngx_module_t ngx_http_dynamic_upstream_module = {
    NGX_MODULE_V1,
    &ngx_http_dynamic_upstream_module_ctx,     /* module context    */
    ngx_http_dynamic_upstream_commands,        /* module directives */
    NGX_HTTP_MODULE,                           /* module type       */
    NULL,                                      /* init master       */
    NULL,                                      /* init module       */
    ngx_http_dynamic_upstream_init_worker,     /* init process      */
    NULL,                                      /* init thread       */
    NULL,                                      /* exit thread       */
#if (NGX_THREADS)
    NULL,
#else
    ngx_http_dynamic_upstream_exit_worker,     /* exit process      */
#endif
    NULL,                                      /* exit master       */
    NGX_MODULE_V1_PADDING
};


ngx_module_t ngx_stream_dynamic_upstream_module = {
    NGX_MODULE_V1,
    &ngx_stream_dynamic_upstream_module_ctx,   /* module context    */
    ngx_stream_dynamic_upstream_commands,      /* module directives */
    NGX_STREAM_MODULE,                         /* module type       */
    NULL,                                      /* init master       */
    NULL,                                      /* init module       */
    NULL,                                      /* init process      */
    NULL,                                      /* init thread       */
    NULL,                                      /* exit thread       */
    NULL,                                      /* exit process      */
    NULL,                                      /* exit master       */
    NGX_MODULE_V1_PADDING
};


static ngx_file_t
file_open(ngx_str_t *filename, int create, int mode)
{
    ngx_file_t  file;

    file.name = *filename;
    file.offset = 0;
 
    file.fd = ngx_open_file(file.name.data, mode,
                            create, NGX_FILE_DEFAULT_ACCESS);

    return file;
}


static char *
ngx_create_servers_file(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *filename = (ngx_str_t *) data;
    ngx_file_t  file;

    static const ngx_str_t
        default_server = ngx_string("server 0.0.0.0:1 down;");

    if (ngx_conf_full_name(cf->cycle, filename, 1) != NGX_OK)
        return NGX_CONF_ERROR;

    file = file_open(filename, NGX_FILE_OPEN, NGX_FILE_RDONLY);
    if (file.fd != NGX_INVALID_FILE)
        goto done;

    file = file_open(filename, NGX_FILE_CREATE_OR_OPEN, NGX_FILE_WRONLY);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, cf->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", filename);
        return NGX_CONF_ERROR;
    }

    file.log = cf->log;

    if (ngx_write_file(&file, default_server.data, default_server.len, 0)
        == NGX_ERROR) {
        ngx_close_file(file.fd);
        return NGX_CONF_ERROR;
    }

done:

    ngx_close_file(file.fd);

    return ngx_conf_include(cf, NULL, NULL);
}


// parse uri parameters

static ngx_str_t
get_str(ngx_http_request_t *r, const char *arg,
    ngx_dynamic_upstream_op_t *op = NULL, ngx_int_t flag = 0)
{
    ngx_str_t                   name = { 0, (u_char *) alloca(128) }, val;
    ngx_http_variable_value_t  *var;

    name.len = ngx_snprintf(name.data, 128, "arg_%s", arg) - name.data;
    var = ngx_http_get_variable(r, &name, ngx_hash_key(name.data, name.len));

    ngx_str_null(&val);

    if (!var->not_found) {

        if (op != NULL)
            op->op_param |= flag;
        val.data = var->data;
        val.len = var->len;
    }

    return val;
}


static ngx_int_t
get_num(ngx_http_request_t *r, const char *arg,
    ngx_dynamic_upstream_op_t *op = NULL, ngx_int_t flag = 0)
{
    ngx_str_t  v = get_str(r, arg, op, flag);
    ngx_int_t  n;
    if (v.data == NULL)
        return 0;
    n = ngx_atoi(v.data, v.len);
    if (n == NGX_ERROR) {
        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = (const char *) ngx_pcalloc(r->pool, 128);
        ngx_snprintf((u_char *) op->err, 128, "%s: not a number", arg);
        return NGX_ERROR;
    }
    return n;
}


static ngx_int_t
get_bool(ngx_http_request_t *r, const char *arg,
    ngx_dynamic_upstream_op_t *op, ngx_int_t flag = 0)
{
    return get_str(r, arg, op, flag).data != NULL;
}


ngx_int_t
ngx_dynamic_upstream_build_op(ngx_http_request_t *r,
    ngx_dynamic_upstream_op_t *op)
{
    static const ngx_int_t UPDATE_OP_PARAM = (
        NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT
        | NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS
        | NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT
        | NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP
        | NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN
#if defined(nginx_version) && (nginx_version >= 1011005)
        | NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS
#endif
    );

    ngx_memzero(op, sizeof(ngx_dynamic_upstream_op_t));

    op->err = "unexpected";
    op->status = NGX_HTTP_OK;

    op->upstream = get_str(r, "upstream", op);
    if (!op->upstream.data) {

        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = "upstream required";

        return NGX_ERROR;
    }

    op->verbose = get_bool(r, "verbose", op);
    op->backup = get_bool(r, "backup", op);
    op->server = get_str(r, "server", op);
    op->name = get_str(r, "peer", op);
    op->up = get_bool(r, "up", op, NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP);
    op->down = get_bool(r, "down", op, NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN);
    op->weight = get_num(r, "weight", op,
        NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT);
    op->max_fails = get_num(r, "max_fails", op,
        NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS);
    op->fail_timeout = get_num(r, "fail_timeout", op,
        NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT);
#if defined(nginx_version) && (nginx_version >= 1011005)
    op->max_conns = get_num(r, "max_conns", op,
        NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS);
#endif
    get_bool(r, "stream", op, NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM);
    get_bool(r, "ipv6", op, NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6);
    if (get_bool(r, "add", op))
        op->op |= NGX_DYNAMIC_UPSTEAM_OP_ADD;
    if (get_bool(r, "remove", op))
        op->op |= NGX_DYNAMIC_UPSTEAM_OP_REMOVE;

    if (op->status == NGX_HTTP_BAD_REQUEST)
        return NGX_ERROR;

    if (op->op_param & UPDATE_OP_PARAM) {

        op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
        op->verbose = 1;
    }

    /* can not add, sync and remove at once */
    if ((op->op & NGX_DYNAMIC_UPSTEAM_OP_ADD    ? 1 : 0) +
        (op->op & NGX_DYNAMIC_UPSTEAM_OP_REMOVE ? 1 : 0) > 1)
    {

        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = "add and remove at once are not allowed";

        return NGX_ERROR;
    }

    /* can not up and down at once */
    if (op->up && op->down) {

        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = "down and up at once are not allowed";

        return NGX_ERROR;
    }

    if (op->op & NGX_DYNAMIC_UPSTEAM_OP_ADD)

        op->op = NGX_DYNAMIC_UPSTEAM_OP_ADD;

    else if (op->op & NGX_DYNAMIC_UPSTEAM_OP_REMOVE)

        op->op = NGX_DYNAMIC_UPSTEAM_OP_REMOVE;

    else if (op->op == 0)

        op->op = NGX_DYNAMIC_UPSTEAM_OP_LIST;

    if ((op->op & NGX_DYNAMIC_UPSTEAM_OP_ADD) ||
        (op->op & NGX_DYNAMIC_UPSTEAM_OP_REMOVE)) {

        if (op->server.data == NULL) {

            op->err = "'server' argument required";
            op->status = NGX_HTTP_BAD_REQUEST;

            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_dynamic_upstream_srv_conf_t *
srv_conf(ngx_http_upstream_srv_conf_t *uscf)
{
    return uscf != NULL ? (ngx_dynamic_upstream_srv_conf_t *)
        ngx_http_conf_upstream_srv_conf(uscf,
            ngx_http_dynamic_upstream_module) : NULL;
}


static ngx_dynamic_upstream_srv_conf_t *
srv_conf(ngx_stream_upstream_srv_conf_t *uscf)
{
    return uscf != NULL ? (ngx_dynamic_upstream_srv_conf_t *)
        ngx_stream_conf_upstream_srv_conf(uscf,
            ngx_stream_dynamic_upstream_module) : NULL;
}


typedef struct {
    void                             *uscf;
    ngx_dynamic_upstream_srv_conf_t  *dscf;
} ngx_upstream_conf_t;


template <class S> static ngx_upstream_conf_t
ngx_dynamic_upstream_get(ngx_dynamic_upstream_op_t *op)
{
    typename TypeSelect<S>::main_type  *umcf;
    typename TypeSelect<S>::srv_type  **uscf;

    ngx_upstream_conf_t  u;
    ngx_uint_t           j;

    ngx_memzero(&u, sizeof(ngx_upstream_conf_t));

    umcf = TypeSelect<S>::main_conf();

    if (umcf == NULL) {
        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = "module is not configured";
        return u;
    }

    uscf = (S **) umcf->upstreams.elts;

    for (j = 0; j < umcf->upstreams.nelts; j++) {

        if (str_eq(uscf[j]->host, op->upstream)) {

            if (uscf[j]->shm_zone == NULL) {

                op->status = NGX_HTTP_NOT_IMPLEMENTED;
                op->err = "only for upstream with 'zone'";

                return u;
            }

            u.uscf = uscf[j];
            u.dscf = srv_conf(uscf[j]);

            return u;
        }
    }

    op->status = NGX_HTTP_NOT_FOUND;
    op->err = "upstream is not found";

    return u;
}


template <class S> ngx_int_t
ngx_dynamic_upstream_do_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    void *uscfp, ngx_pool_t *temp_pool)
{
    S  *uscf = (S *) uscfp;

    if (temp_pool == NULL) {

        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        op->err = "no memory";

        return NGX_ERROR;
    }

    if (uscf->shm_zone == NULL) {

        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        op->err = "only for upstream with 'zone'";

        return NGX_ERROR;
    }

    return ngx_dynamic_upstream_op_impl(log, op,
        (ngx_slab_pool_t *) uscf->shm_zone->shm.addr, temp_pool,
        uscf->peer.data);
}


ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_int_t    retval;
    ngx_pool_t  *temp_pool;

    temp_pool = ngx_create_pool(1024, log);

    retval = ngx_dynamic_upstream_do_op
        <ngx_http_upstream_srv_conf_t>(log, op, uscf, temp_pool);

    if (temp_pool != NULL)
        ngx_destroy_pool(temp_pool);
    
    return retval;
}


ngx_int_t
ngx_dynamic_upstream_stream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_int_t    retval;
    ngx_pool_t  *temp_pool;

    temp_pool = ngx_create_pool(1024, log);

    retval = ngx_dynamic_upstream_do_op
        <ngx_stream_upstream_srv_conf_t>(log, op, uscf, temp_pool);

    if (temp_pool != NULL)
        ngx_destroy_pool(temp_pool);
    
    return retval;
}


template <class S> static void
ngx_dynamic_upstream_print_response(void *uscfp,
    ngx_buf_t *b, ngx_int_t verbose)
{
    S  *uscf = (S *) uscfp;

    typename TypeSelect<S>::peers_type  *peers;
    typename TypeSelect<S>::peer_type   *peer;

    ngx_uint_t  j;

    peers = (typename TypeSelect<S>::peers_type *) uscf->peer.data;

    ngx_upstream_peers_rlock<typename TypeSelect<S>::peers_type> lock(peers);

    for (j = 0; peers != NULL && j < 2; peers = peers->next, j++) {

        for (peer = peers->peer; peer != NULL; peer = peer->next) {

            if (verbose) {

                b->last = ngx_snprintf(b->last, b->end - b->last,
                    "server %V addr=%V weight=%d max_fails=%d fail_timeout=%d"
#if defined(nginx_version) && (nginx_version >= 1011005)
                    " max_conns=%d"
#endif
                    " conns=%d",
                    &peer->server, &peer->name, peer->weight, peer->max_fails,
                    peer->fail_timeout,
#if defined(nginx_version) && (nginx_version >= 1011005)
                    peer->max_conns,
#endif
                    peer->conns);

            } else
                b->last = ngx_snprintf(b->last, b->end - b->last,
                                       "server %V addr=%V", &peer->server,
                                       &peer->name);

            if (peer->down)
                b->last = ngx_snprintf(b->last, b->end - b->last, " down");

            if (j == 1)
                b->last = ngx_snprintf(b->last, b->end - b->last, " backup");

            b->last =  ngx_snprintf(b->last, b->end - b->last, ";\n");
        }
    }
}


static void
ngx_dynamic_upstream_response(ngx_upstream_conf_t *conf,
    ngx_buf_t *b, ngx_dynamic_upstream_op_t *op)
{
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM)
        return ngx_dynamic_upstream_print_response
            <ngx_stream_upstream_srv_conf_t>(conf->uscf, b, op->verbose);

    ngx_dynamic_upstream_print_response
        <ngx_http_upstream_srv_conf_t>(conf->uscf, b, op->verbose);
}


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc = NGX_ERROR;
    ngx_dynamic_upstream_op_t    op;
    ngx_buf_t                   *b;
    ngx_upstream_conf_t          conf;
    ngx_http_complex_value_t     cv;

    if (r->method != NGX_HTTP_GET) {

        op.err = "only GET allowed";
        op.status = NGX_HTTP_NOT_ALLOWED;

        goto response;
    }

    if ((rc = ngx_dynamic_upstream_build_op(r, &op)) != NGX_OK)
        goto response;

    if (op.op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM)
        conf = ngx_dynamic_upstream_get
                    <ngx_stream_upstream_srv_conf_t>(&op);
    else
        conf = ngx_dynamic_upstream_get
                    <ngx_http_upstream_srv_conf_t>(&op);

    if (conf.uscf != NULL) {

        if (conf.dscf->interval != NGX_CONF_UNSET_MSEC)
            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;

        if (conf.dscf->ipv6 == 1)
            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;

        if (op.op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM)
            rc = ngx_dynamic_upstream_do_op
                    <ngx_stream_upstream_srv_conf_t>(r->connection->log, &op,
                        conf.uscf, r->pool);
        else
            rc = ngx_dynamic_upstream_do_op
                    <ngx_http_upstream_srv_conf_t>(r->connection->log, &op,
                        conf.uscf, r->pool);
    } else
        rc = NGX_ERROR;

response:

    static ngx_str_t TEXT_PLAIN = ngx_string("text/plain");

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    if (rc == NGX_OK) {

        if (op.status != NGX_HTTP_NOT_MODIFIED) {

            b = ngx_create_temp_buf(r->pool, ngx_pagesize * 32);
            if (b == NULL) {

                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no memory");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            ngx_dynamic_upstream_response(&conf, b, &op);

            cv.value.len = b->last - b->start;
            cv.value.data = b->start;
        }

    } else {

        if (op.status == NGX_HTTP_INTERNAL_SERVER_ERROR) {

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V: %s",
                          &op.upstream, op.err);
        }

        cv.value.len = strlen(op.err);
        cv.value.data = (u_char *) op.err;
    }

    return ngx_http_send_response(r, op.status, &TEXT_PLAIN, &cv);
}


static char *
ngx_dynamic_upstream_dns_update(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_THREADS)

    ngx_dynamic_upstream_srv_conf_t  *dscf;
    ngx_str_t                        *arg;

#endif

    if (ngx_conf_set_msec_slot(cf, cmd, conf) == NGX_CONF_ERROR)
        return NGX_CONF_ERROR;

#if (NGX_THREADS)

    dscf = (ngx_dynamic_upstream_srv_conf_t *) conf;
    arg = (ngx_str_t *) cf->args->elts;

    dscf->thread_pool = ngx_thread_pool_add(cf, cf->args->nelts == 3 ? arg + 2 :
                                            NULL);
    if (dscf->thread_pool == NULL)
        return NGX_CONF_ERROR;

#endif

    return NGX_CONF_OK;
}


static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = (ngx_http_core_loc_conf_t *) ngx_http_conf_get_module_loc_conf(cf,
        ngx_http_core_module);
    clcf->handler = ngx_dynamic_upstream_handler;

    return NGX_CONF_OK;
}


static void *
ngx_dynamic_upstream_create_srv_conf(ngx_conf_t *cf)
{
    ngx_dynamic_upstream_srv_conf_t  *conf;

    conf = (ngx_dynamic_upstream_srv_conf_t *)
        ngx_pcalloc(cf->pool, sizeof(ngx_dynamic_upstream_srv_conf_t));
    if (conf == NULL)
        return NULL;

    conf->interval = NGX_CONF_UNSET_MSEC;
    conf->next = 0;
    conf->ipv6 = NGX_CONF_UNSET;
    conf->add_down = NGX_CONF_UNSET;

    return conf;
}


template <class PeerT> ngx_int_t
not_resolved(PeerT *peer)
{
    extern ngx_int_t is_reserved_addr(ngx_str_t *addr);
    return is_reserved_addr(&peer->name) && !is_reserved_addr(&peer->server);
}


#define ngx_array_push_str(a) ((ngx_str_t *) ngx_array_push(a))


template <class S> void
ngx_http_dynamic_upstream_save(S *uscf, ngx_str_t filename,
    ngx_pool_t *temp_pool)
{
    typename TypeSelect<S>::peers_type  *peers;
    typename TypeSelect<S>::peer_type   *peer;

    ngx_uint_t    j, i;
    ngx_file_t    file;
    ngx_array_t  *servers;
    ngx_str_t    *server, *s;
    u_char       *start, *end, *last;

    static const ngx_str_t
        default_server = ngx_string("server 0.0.0.0:1 down;");

    if (filename.data == NULL)
        return;

    peers = (typename TypeSelect<S>::peers_type *) uscf->peer.data;

    ngx_upstream_peers_rlock<typename TypeSelect<S>::peers_type> lock(peers);

    start = (u_char *) ngx_palloc(temp_pool, ngx_pagesize);
    if (start == NULL)
        goto nomem;
    end = start + ngx_pagesize;

    servers = ngx_array_create(temp_pool, 100, sizeof(ngx_str_t));
    if (servers == NULL)
        goto nomem;

    file.name = filename;
    file.offset = 0;
 
    file.fd = ngx_open_file(filename.data, NGX_FILE_WRONLY,
                            NGX_FILE_TRUNCATE, NGX_FILE_DEFAULT_ACCESS);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                      ngx_open_file_n " \"%V\" failed", &filename);
        return;
    }

    server = (ngx_str_t *) servers->elts;

    for (j = 0; peers != NULL && j < 2; peers = peers->next, j++) {

        for (peer = peers->peer; peer != NULL; peer = peer->next) {

            if (not_resolved(peer))
                continue;

            for (i = 0; i < servers->nelts; i++)
                if (ngx_memn2cmp(peer->server.data, server[i].data,
                                 peer->server.len, server[i].len) == 0)
                    // already saved
                    break;

            if (i == servers->nelts) {

                s = ngx_array_push_str(servers);
                if (s == NULL)
                    goto nomem;

                ngx_memcpy(s, &peer->server, sizeof(ngx_str_t));

                last = ngx_snprintf(start, end - start,
                                    "server %V"
                                    " max_conns=%d"
                                    " max_fails=%d"
                                    " fail_timeout=%d"
                                    " weight=%d",
                                    &peer->server,
                                    peer->max_conns,
                                    peer->max_fails,
                                    peer->fail_timeout,
                                    peer->weight);

                if (j == 1)
                    last = ngx_snprintf(last, end - last, " backup");

                last = ngx_snprintf(last, end - last, ";\n");

                if (ngx_write_file(&file, start, last - start, file.offset)
                        == NGX_ERROR)
                    goto fail;
            }
        }
    }

    if (file.offset != 0)
        goto end;

    if (ngx_write_file(&file, default_server.data, default_server.len, 0)
            == NGX_ERROR)
        goto fail;

end:

    ngx_close_file(file.fd);
    return;

nomem:

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "dynamic upstream: no memory");
    goto end;

fail:

    ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, ngx_errno,
                  ngx_write_fd_n " \"%V\" failed", &filename);
    ngx_delete_file(filename.data);

    goto end;
}


typedef struct {
    void        *uscf;
    ngx_pool_t  *temp_pool;
} thread_ctx_t;


template <class S> struct upstream_sync_functor
{
    static void sync(void *ctxp, ngx_log_t *log)
    {
        thread_ctx_t                     *ctx = (thread_ctx_t *) ctxp;
        S                                *uscf = (S *) ctx->uscf;
        ngx_dynamic_upstream_op_t         op;
        ngx_dynamic_upstream_srv_conf_t  *dscf = srv_conf(uscf);
        ngx_time_t                       *tp;
        ngx_msec_t                        now;
        ngx_uint_t                        old_hash;

        ngx_memzero(&op, sizeof(ngx_dynamic_upstream_op_t));

        op.err = "unexpected";
        op.status = NGX_HTTP_OK;

        TypeSelect<S>::make_op(&op);

        old_hash = op.hash = dscf->hash;

        if (dscf->interval == NGX_CONF_UNSET_MSEC) {

            if (dscf->file.data != NULL) {

                op.op = NGX_DYNAMIC_UPSTEAM_OP_HASH;
                if (ngx_dynamic_upstream_do_op<S>(log, &op, uscf,
                        ctx->temp_pool) == NGX_DECLINED)
                    goto save;
            }

            return;
        }

        ngx_time_update();

        tp = ngx_timeofday();
        now = tp->sec * 1000 + tp->msec;

        if (dscf->next > now)
            return;

        dscf->next = now + dscf->interval;

        op.op = NGX_DYNAMIC_UPSTEAM_OP_SYNC;
        op.hash = 0;
        op.upstream = uscf->host;
        op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE_SYNC;
        if (dscf->ipv6 == 1)
            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;
        if (dscf->add_down != NGX_CONF_UNSET && dscf->add_down) {
            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN;
            op.down = 1;
        }

        if (ngx_dynamic_upstream_do_op<S>(log, &op, uscf, ctx->temp_pool)
                == NGX_OK) {

            if (op.status == NGX_HTTP_OK)
                ngx_log_error(NGX_LOG_INFO, log, 0,
                              "%V: dns synced", &op.upstream);

        } else if (op.status == NGX_HTTP_INTERNAL_SERVER_ERROR)
            ngx_log_error(NGX_LOG_ERR, log, 0, "%V: %s",
                          &op.upstream, op.err);

    save:

        if (old_hash != op.hash) {
            ngx_http_dynamic_upstream_save<S>(uscf, dscf->file, ctx->temp_pool);
            dscf->hash = op.hash;
        }
    }

#if (NGX_THREADS)

    static void completion(ngx_event_t *ev)
    {
        thread_ctx_t                     *ctx = (thread_ctx_t *) ev->data;
        S                                *uscf = (S *) ctx->uscf;
        ngx_dynamic_upstream_srv_conf_t  *dscf = srv_conf(uscf);

        dscf->busy = 0;

        ngx_destroy_pool(ctx->temp_pool);
    }

#endif

};


#if (NGX_THREADS)

template <class S> void
ngx_dynamic_upstream_loop()

#else

template <class S> void
ngx_dynamic_upstream_loop(ngx_uint_t nelts, ngx_pool_t *temp_pool)

#endif

{
    typename TypeSelect<S>::main_type   *umcf;
    typename TypeSelect<S>::srv_type   **uscf;
    ngx_uint_t                           j;
    ngx_core_conf_t                     *ccf;
    ngx_dynamic_upstream_srv_conf_t     *dscf;

#if (NGX_THREADS)

    ngx_pool_t                          *temp_pool;
    thread_ctx_t                        *ctx;
    ngx_thread_task_t                   *task;

#else

    thread_ctx_t                         ctx;

#endif

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    umcf = TypeSelect<S>::main_conf();
    if (umcf == NULL)
        return;

    uscf = (S **) umcf->upstreams.elts;
    if (uscf == NULL)
        return;

#if (NGX_THREADS)

    for (j = 0; j < umcf->upstreams.nelts; j++) {

#else

    for (j = 0; j < nelts; j++) {

#endif

        if (uscf[j]->srv_conf == NULL || uscf[j]->shm_zone == NULL)
            continue;

        if (ngx_process == NGX_PROCESS_WORKER
            && j % ccf->worker_processes != ngx_worker)
            continue;

        dscf = srv_conf(uscf[j]);

        if (dscf->file.data == NULL && dscf->interval == NGX_CONF_UNSET_MSEC)
            continue;

#if (NGX_THREADS)

        if (dscf->busy)
            continue;

        temp_pool = ngx_create_pool(1024, ngx_cycle->log);
        if (temp_pool == NULL)
            return;

        if (dscf->interval != NGX_CONF_UNSET_MSEC) {

            task = ngx_thread_task_alloc(temp_pool, sizeof(thread_ctx_t));
            if (task == NULL)
                goto fail;

            ctx = (thread_ctx_t *) task->ctx;
            ctx->temp_pool = temp_pool;
            ctx->uscf = uscf[j];

            task->handler = &upstream_sync_functor<S>::sync;
            task->event.handler = &upstream_sync_functor<S>::completion;
            task->event.data = ctx;

            dscf->busy = 1;

            if (ngx_thread_task_post(dscf->thread_pool, task) != NGX_OK)
                goto fail;

        } else {

            ctx = (thread_ctx_t *) ngx_palloc(temp_pool, sizeof(thread_ctx_t));
            if (ctx == NULL)
                goto fail;

            ctx->temp_pool = temp_pool;
            ctx->uscf = uscf[j];

            upstream_sync_functor<S>::sync(ctx, ngx_cycle->log);

            ngx_destroy_pool(temp_pool);
        }

        continue;

fail:

        dscf->busy = 0;

        ngx_destroy_pool(temp_pool);

        return;

#else

        ctx.temp_pool = temp_pool;
        ctx.uscf = uscf[j];

        upstream_sync_functor<S>::sync(&ctx, ngx_cycle->log);

#endif
    }
}


#if (NGX_THREADS)

static void
ngx_http_dynamic_upstream_sync(ngx_event_t *ev)
{
    if (ngx_quit || ngx_terminate || ngx_exiting)
        return;

    ngx_dynamic_upstream_loop<ngx_http_upstream_srv_conf_t>();

    ngx_dynamic_upstream_loop<ngx_stream_upstream_srv_conf_t>();

    ngx_add_timer(ev, 500);
}

#else


template <class S> class upstream_sync_thread {
    
    ngx_uint_t  count;
    pthread_t   tid;

    static void * run(void *pctx)
    {
        upstream_sync_thread<S>  *ctx = (upstream_sync_thread<S> *) pctx;
        ngx_pool_t               *temp_pool;

        while (ctx->tid) {

            temp_pool = ngx_create_pool(1024, ngx_cycle->log);

            if (temp_pool != NULL) {

                ngx_dynamic_upstream_loop<S>(ctx->count, temp_pool);

                ngx_destroy_pool(temp_pool);
            }

            ngx_msleep(500);
        }

        return 0;
    }

public:

    static upstream_sync_thread<S>  *instance;

    upstream_sync_thread() : count(0), tid(0) {
        typename TypeSelect<S>::main_type  *umcf = TypeSelect<S>::main_conf();
        if (umcf != NULL)
            count = umcf->upstreams.nelts;
    }

    ngx_int_t start() {
        if (count == 0)
            return NGX_DECLINED;

        if (pthread_create(&tid, NULL, run, (void *) this) != 0)
            return NGX_ERROR;

        return NGX_OK;
    }

    void join() {
        pthread_t  wait_tid = tid;

        if (!wait_tid)
            return;

        tid = 0;

        pthread_join(wait_tid, NULL);
    }
};


template <class S> class upstream_sync_thread<S> *
    upstream_sync_thread<S>::instance;


typedef upstream_sync_thread<ngx_http_upstream_srv_conf_t>
    ngx_http_upsync_t;
typedef upstream_sync_thread<ngx_stream_upstream_srv_conf_t>
    ngx_stream_upsync_t;


static void
ngx_http_dynamic_upstream_exit_worker(ngx_cycle_t *)
{
    if (ngx_http_upsync_t::instance != NULL)
        ngx_http_upsync_t::instance->join();
    if (ngx_stream_upsync_t::instance != NULL)
        ngx_stream_upsync_t::instance->join();
}

#endif


static ngx_int_t
ngx_http_dynamic_upstream_init_worker(ngx_cycle_t *cycle)
{
#if (NGX_THREADS)

    ngx_event_t       *ev;
    ngx_connection_t   c;

    c.fd = -1;

#else

    void  *p;

#endif

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

#if (NGX_THREADS)

    ev = (ngx_event_t *) ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (ev == NULL)
        return NGX_ERROR;

    ev->log = cycle->log;
    ev->data = &c;
    ev->handler = ngx_http_dynamic_upstream_sync;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "dynamic upstream: using nginx thread pool");

    ngx_http_dynamic_upstream_sync(ev);

    return NGX_OK;

#else

    ngx_http_upsync_t::instance = NULL;
    ngx_stream_upsync_t::instance = NULL;

    p = ngx_palloc(cycle->pool, sizeof(ngx_http_upsync_t));
    if (p == NULL)
        return NGX_ERROR;
    ngx_http_upsync_t::instance = new (p) ngx_http_upsync_t();

    p = ngx_palloc(cycle->pool, sizeof(ngx_stream_upsync_t));
    if (p == NULL)
        return NGX_ERROR;
    ngx_stream_upsync_t::instance = new (p) ngx_stream_upsync_t();

    if (ngx_http_upsync_t::instance->start() == NGX_ERROR)
        goto fail;

    if (ngx_stream_upsync_t::instance->start() == NGX_ERROR)
        goto fail;

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "dynamic upstream: using background threads");

    return NGX_OK;

fail:

    ngx_log_error(NGX_LOG_CRIT, cycle->log, ngx_errno,
                  "dynamic upstream initialization failed");

    return NGX_ERROR;

#endif
}
