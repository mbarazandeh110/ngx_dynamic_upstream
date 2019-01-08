/*
 * Copyright (c) 2015 Tatsuhiko Kubo (cubicdaiya@gmail.com>)
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

extern "C" {

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <pthread.h>
#include <errno.h>

}

#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"


static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_int_t
ngx_http_dynamic_upstream_init_worker(ngx_cycle_t *cycle);

static void
ngx_http_dynamic_upstream_exit_worker(ngx_cycle_t *cycle);


static void *
ngx_dynamic_upstream_create_srv_conf(ngx_conf_t *cf);


static char *
ngx_create_servers_file(ngx_conf_t *cf, void *post, void *data);


typedef struct {
    ngx_msec_t  interval;
    time_t      last;
    ngx_uint_t  hash;
    ngx_flag_t  ipv6;
    ngx_flag_t  add_down;
    ngx_str_t   file;
} ngx_dynamic_upstream_srv_conf_t;

static char *
ngx_create_servers_file(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_servers_file_post = {
    ngx_create_servers_file
};

static ngx_conf_num_bounds_t  ngx_check_update = {
    ngx_conf_check_num_bounds,
    1, 3600
};

static ngx_command_t ngx_http_dynamic_upstream_commands[] = {

    { ngx_string("dynamic_upstream"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_dynamic_upstream,
      0,
      0,
      NULL },

    { ngx_string("dns_update"),
      NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
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

    {
        ngx_string("dns_update"),
        NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_dynamic_upstream_srv_conf_t, interval),
        NULL
    },

    {
        ngx_string("dns_add_down"),
        NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_dynamic_upstream_srv_conf_t, add_down),
        NULL
    },

    {
        ngx_string("dns_ipv6"),
        NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_STREAM_SRV_CONF_OFFSET,
        offsetof(ngx_dynamic_upstream_srv_conf_t, ipv6),
        NULL
    },

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
    ngx_http_dynamic_upstream_exit_worker,     /* exit process      */
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


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r);


static FILE *
state_open(ngx_str_t *state_file, const char *mode)
{
    FILE  *f;

    f = fopen((const char *) state_file->data, mode);
    if (f == NULL)
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "can't open file: %V",
                      state_file);

    return f;
}


static char *
ngx_create_servers_file(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *fname = (ngx_str_t *) data;
    FILE       *f;

    static const ngx_str_t
        default_server = ngx_string("server 0.0.0.0:1 down;");

    if (ngx_conf_full_name(cf->cycle, fname, 1) != NGX_OK)
        return (char *) NGX_CONF_ERROR;

    f = state_open(fname, "r");
    if (f != NULL) {
        fclose(f);
        return ngx_conf_include(cf, NULL, NULL);
    }

    f = state_open(fname, "w+");
    if (f == NULL)
        return (char *) NGX_CONF_ERROR;

    fwrite(default_server.data, default_server.len, 1, f);

    fclose(f);

    return ngx_conf_include(cf, NULL, NULL);
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
    ngx_uint_t           i;

    ngx_memzero(&u, sizeof(ngx_upstream_conf_t));
    
    umcf = TypeSelect<S>::main_conf();
    uscf = (S **) umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscf[i]->host.len == op->upstream.len
            && ngx_strncmp(uscf[i]->host.data, op->upstream.data,
                           op->upstream.len) == 0) {

            if (uscf[i]->shm_zone == NULL) {

                op->status = NGX_HTTP_NOT_IMPLEMENTED;
                op->err = "only for upstream with 'zone'";

                return u;
            }

            u.uscf = uscf[i];
            u.dscf = srv_conf(uscf[i]);

            return u;
        }
    }

    op->status = NGX_HTTP_NOT_FOUND;
    op->err = "upstream is not found";

    return u;
}


extern "C" ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_http_upstream_srv_conf_t *uscf)
{
    if (uscf->shm_zone == NULL) {

        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        op->err = "only for upstream with 'zone'";

        return NGX_ERROR;
    }

    return ngx_dynamic_upstream_op_impl(log, op,
        (ngx_slab_pool_t *) uscf->shm_zone->shm.addr, uscf->peer.data);
}


static ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    if (uscf->shm_zone == NULL) {

        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        op->err = "only for upstream with 'zone'";

        return NGX_ERROR;
    }

    return ngx_dynamic_upstream_op_impl(log, op,
        (ngx_slab_pool_t *) uscf->shm_zone->shm.addr, uscf->peer.data);
}


extern "C" ngx_int_t
ngx_dynamic_upstream_stream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    return ngx_dynamic_upstream_op(log, op, uscf);
}


template <class S> static void
ngx_dynamic_upstream_response_impl(void *uscf,
    ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    typename TypeSelect<S>::peers_type  *peers, *backup;
    typename TypeSelect<S>::peer_type   *peer;

    u_char     *last = b->last + size;
    ngx_uint_t  i;

    peers = (typename TypeSelect<S>::peers_type *) (((S *) uscf)->peer.data);
    backup = (typename TypeSelect<S>::peers_type *) peers->next;

    ngx_upstream_rr_peers_rlock<typename TypeSelect<S>::peers_type> lock(peers);

    for (i = 0; peers && i < 2; peers = peers->next, i++) {
        for (peer = peers->peer; peer; peer = peer->next) {
            
            if (verbose) {
                b->last = ngx_snprintf(b->last, last - b->last,
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
                b->last = ngx_snprintf(b->last, last - b->last,
                                       "server %V addr=%V", &peer->server,
                                       &peer->name);

            b->last = peer->down
                ? ngx_snprintf(b->last, last - b->last, " down")
                : ngx_snprintf(b->last, last - b->last, "");
            b->last = peers == backup
                ? ngx_snprintf(b->last, last - b->last, " backup;\n")
                : ngx_snprintf(b->last, last - b->last, ";\n");
        }
    }
}


static void
ngx_dynamic_upstream_response(ngx_upstream_conf_t *conf,
    ngx_buf_t *b, size_t size, ngx_dynamic_upstream_op_t *op)
{
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM)
        ngx_dynamic_upstream_response_impl
            <ngx_stream_upstream_srv_conf_t>(conf->uscf, b, size, op->verbose);
    else
        ngx_dynamic_upstream_response_impl
            <ngx_http_upstream_srv_conf_t>(conf->uscf, b, size, op->verbose);
}


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc = NGX_ERROR;
    ngx_chain_t                  out;
    ngx_dynamic_upstream_op_t    op;
    ngx_buf_t                   *b;
    ngx_upstream_conf_t          conf;

    if (r->method != NGX_HTTP_GET) {
        op.err = "only GET allowed";
        op.status = NGX_HTTP_NOT_ALLOWED;
        goto resp;
    }

    if ((rc = ngx_http_discard_request_body(r)) != NGX_OK)
        return rc;

    if ((rc = ngx_dynamic_upstream_build_op(r, &op)) != NGX_OK)
        goto resp;

    if (op.op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM)
        conf = ngx_dynamic_upstream_get
                    <ngx_stream_upstream_srv_conf_t>(&op);
    else
        conf = ngx_dynamic_upstream_get
                    <ngx_http_upstream_srv_conf_t>(&op);

    if (conf.uscf == NULL) {
        rc = NGX_ERROR;
        goto resp;
    }

    if (conf.dscf->interval != NGX_CONF_UNSET_MSEC)
        op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;
    if (conf.dscf->ipv6 == 1)
        op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;

    if (op.op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM)
        rc = ngx_dynamic_upstream_op(r->connection->log, &op,
                (ngx_stream_upstream_srv_conf_t *) conf.uscf);
    else
        rc = ngx_dynamic_upstream_op(r->connection->log, &op,
                (ngx_http_upstream_srv_conf_t *) conf.uscf);

resp:

    static const size_t size = ngx_pagesize * 100;
    static const ngx_str_t text = ngx_string("text/plain");

    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no memory");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    r->headers_out.status = op.status;

    if (rc == NGX_OK)
        ngx_dynamic_upstream_response(&conf, b, size, &op);
    else {
        if (op.status == NGX_HTTP_INTERNAL_SERVER_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V: %s",
                          &op.upstream, op.err);
        }
        b->last = ngx_snprintf(b->last, size, op.err);
    }

    r->headers_out.content_type = text;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    ngx_http_send_header(r);

    return ngx_http_output_filter(r, &out);
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
    conf->last = 0;
    conf->ipv6 = NGX_CONF_UNSET;
    conf->add_down = NGX_CONF_UNSET;

    return conf;
}


template <class S> void
ngx_http_dynamic_upstream_save(S *uscf, ngx_str_t file)
{
    typename TypeSelect<S>::peer_type   *peer;
    typename TypeSelect<S>::peers_type  *peers, *primary;

    ngx_uint_t       j = 0;
    u_char           srv[10240], *c;
    FILE            *f;
    ngx_pool_t      *pool;
    ngx_array_t     *servers;
    ngx_str_t       *server, *s;
    ngx_uint_t       i;

    pool = ngx_create_pool(2048, ngx_cycle->log);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                      "dynamic upstream: no memory");
        return;
    }

    f = state_open(&file, "w+");
    if (f == NULL) {
        ngx_destroy_pool(pool);
        return;
    }

    primary = (typename TypeSelect<S>::peers_type *) uscf->peer.data;

    ngx_rwlock_rlock(&primary->rwlock);

    servers = ngx_array_create(pool, 100, sizeof(ngx_str_t));
    if (servers == NULL)
        goto nomem;

    server = (ngx_str_t *) servers->elts;

    for (peers = primary;
         peers && j < 2;
         peers = peers->next, j++) {

        for (peer = peers->peer;
             peer;
             peer = peer->next) {

            for (i = 0; i < servers->nelts; i++)
                if (ngx_memn2cmp(peer->server.data, server[i].data,
                                 peer->server.len, server[i].len) == 0)
                    // already saved
                    break;

            if (i == servers->nelts) {
                s = (ngx_str_t *) ngx_array_push(servers);
                if (s == NULL)
                    goto nomem;
                *s = peer->server;
                c = ngx_snprintf(srv, 10240,
                    "server %V max_conns=%d max_fails=%d fail_timeout=%d "
                    "weight=%d",
                    &peer->server, peer->max_conns, peer->max_fails,
                    peer->fail_timeout, peer->weight);
                fwrite(srv, c - srv, 1, f);
                if (j == 1)
                    fwrite(" backup", 7, 1, f);
                fwrite(";\n", 2, 1, f);
            }
        }
    }

end:

    ngx_rwlock_unlock(&primary->rwlock);

    fclose(f);

    ngx_destroy_pool(pool);

    return;

nomem:

    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0,
                  "dynamic upstream: no memory");
    goto end;
}


template <class M, class S> void
ngx_dynamic_upstream_loop()
{
    M                                *umcf = NULL;
    S                               **uscf = NULL;
    ngx_dynamic_upstream_op_t         op;
    ngx_uint_t                        j;
    ngx_dynamic_upstream_srv_conf_t  *dscf;
    time_t                            now = 0;
    ngx_core_conf_t                  *ccf;
    ngx_uint_t                        old_hash;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    umcf = TypeSelect<S>::main_conf();
    if (umcf == NULL)
        return;

    uscf = (S **) umcf->upstreams.elts;
    if (uscf == NULL)
        return;

    for (j = 0; j < umcf->upstreams.nelts; j++) {

        if (uscf[j]->shm_zone == NULL)
            continue;

        if (ngx_process == NGX_PROCESS_WORKER
            && j % ccf->worker_processes != ngx_worker)
            continue;

        dscf = srv_conf(uscf[j]);

        ngx_memzero(&op, sizeof(ngx_dynamic_upstream_op_t));

        op.err = "unexpected";
        op.status = NGX_HTTP_OK;

        TypeSelect<S>::make_op(&op);

        old_hash = op.hash = dscf->hash;

        if (dscf->interval == NGX_CONF_UNSET_MSEC) {

            if (dscf->file.data != NULL) {

                op.op = NGX_DYNAMIC_UPSTEAM_OP_HASH;
                if (ngx_dynamic_upstream_op(ngx_cycle->log, &op, uscf[j])
                        == NGX_DECLINED)
                    goto save;
            }

            continue;
        }

        time(&now);

        if (dscf->last + (time_t) dscf->interval <= now) {

            dscf->hash = 0;
            dscf->last = now;
        }

        op.op = NGX_DYNAMIC_UPSTEAM_OP_SYNC;
        op.upstream = uscf[j]->host;
        op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE_SYNC;
        if (dscf->ipv6 == 1)
            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;
        if (dscf->add_down != NGX_CONF_UNSET && dscf->add_down) {

            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN;
            op.down = 1;
        }

        ngx_time_update();

        if (ngx_dynamic_upstream_op(ngx_cycle->log, &op, uscf[j]) == NGX_OK) {

            if (op.status == NGX_HTTP_OK)
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                              "%V: dns synced", &op.upstream);

        } else if (op.status == NGX_HTTP_INTERNAL_SERVER_ERROR)
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "%V: %s",
                          &op.upstream, op.err);

save:

        if (old_hash != op.hash) {

            if (dscf->file.data != NULL)
                ngx_http_dynamic_upstream_save(uscf[j], dscf->file);

            dscf->hash = op.hash;
        }
    }
}


static volatile pthread_t
DNS_sync_thr = 0;


static void *
ngx_http_dynamic_upstream_thread(void *)
{
    unsigned j;

    while (DNS_sync_thr) {
        ngx_dynamic_upstream_loop<ngx_http_upstream_main_conf_t,
                                  ngx_http_upstream_srv_conf_t>();

        ngx_dynamic_upstream_loop<ngx_stream_upstream_main_conf_t,
                                  ngx_stream_upstream_srv_conf_t>();

        for (j = 0; j < 10 && DNS_sync_thr; j++)
            ngx_msleep(100);
    }

    return 0;
}


static ngx_int_t
ngx_http_dynamic_upstream_init_worker(ngx_cycle_t *cycle)
{
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return NGX_OK;

    if (pthread_create((pthread_t *) &DNS_sync_thr, NULL,
        ngx_http_dynamic_upstream_thread, NULL) != 0) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                      "errno=%d, %s", errno, strerror(errno));
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "dynamic upstream: background thread started");

    return NGX_OK;
}


static void
ngx_http_dynamic_upstream_exit_worker(ngx_cycle_t *cycle)
{
    pthread_t saved = DNS_sync_thr;

    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE)
        return;

    if (DNS_sync_thr) {
        DNS_sync_thr = 0;
        pthread_join(saved, NULL);
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "dynamic upstream: background thread stopped");
    }
}
