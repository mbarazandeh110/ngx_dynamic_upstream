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


struct ngx_dynamic_upstream_srv_conf_s {
    ngx_msec_t interval;
    time_t     last;
    ngx_flag_t ipv6;
};
typedef struct ngx_dynamic_upstream_srv_conf_s
    ngx_dynamic_upstream_srv_conf_t;


static ngx_command_t ngx_http_dynamic_upstream_commands[] = {
    {
        ngx_string("dynamic_upstream"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_dynamic_upstream,
        0,
        0,
        NULL
    },

    {
        ngx_string("dns_update"),
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_sec_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_dynamic_upstream_srv_conf_t, interval),
        NULL
    },

    {
        ngx_string("dns_ipv6"),
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_dynamic_upstream_srv_conf_t, ipv6),
        NULL
    },

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


static ngx_dynamic_upstream_srv_conf_t *
ngx_dynamic_upstream_get_conf(ngx_http_upstream_srv_conf_t *uscf);


static ngx_dynamic_upstream_srv_conf_t *
ngx_dynamic_upstream_get_conf(ngx_stream_upstream_srv_conf_t *uscf);


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r);


typedef struct {
    ngx_http_upstream_srv_conf_t    *http;
    ngx_stream_upstream_srv_conf_t  *stream;
    ngx_slab_pool_t                 *shpool;
    void                            *peers;
} ngx_upstream_srv_conf_t;


template <class M, class S> static S *
ngx_dynamic_upstream_get(M *umcf, S **uscf,
    ngx_dynamic_upstream_op_t *op, ngx_upstream_srv_conf_t *conf)
{
    ngx_uint_t i;

    if (umcf == NULL || uscf == NULL)
        return NULL;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscf[i]->host.len == op->upstream.len &&
            ngx_strncmp(uscf[i]->host.data, op->upstream.data,
                        op->upstream.len) == 0) {
            if (uscf[i]->shm_zone == NULL) {
                op->status = NGX_HTTP_NOT_IMPLEMENTED;
                op->err = "only for upstream with 'zone'";
                return NULL;
            }
            conf->shpool = (ngx_slab_pool_t *) uscf[i]->shm_zone->shm.addr;
            conf->peers = uscf[i]->peer.data;
            return uscf[i];
        }
    }

    return NULL;
}


static ngx_http_upstream_srv_conf_t *
ngx_http_dynamic_upstream_get(ngx_dynamic_upstream_op_t *op,
    ngx_upstream_srv_conf_t *conf)
{
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = (ngx_http_upstream_main_conf_t *)
        ngx_http_cycle_get_module_main_conf(ngx_cycle,
                                            ngx_http_upstream_module);

    return ngx_dynamic_upstream_get
        <ngx_http_upstream_main_conf_t, ngx_http_upstream_srv_conf_t>
            (umcf, (ngx_http_upstream_srv_conf_t **) umcf->upstreams.elts,
                op, conf);
}


static ngx_stream_upstream_srv_conf_t *
ngx_stream_dynamic_upstream_get(ngx_dynamic_upstream_op_t *op,
    ngx_upstream_srv_conf_t *conf)
{
    ngx_stream_upstream_main_conf_t *umcf;

    umcf = (ngx_stream_upstream_main_conf_t *)
        ngx_stream_cycle_get_module_main_conf(ngx_cycle,
                                              ngx_stream_upstream_module);

    return ngx_dynamic_upstream_get
        <ngx_stream_upstream_main_conf_t, ngx_stream_upstream_srv_conf_t>
            (umcf, (ngx_stream_upstream_srv_conf_t **) umcf->upstreams.elts,
                op, conf);
}


static ngx_int_t
ngx_dynamic_upstream_get_conf(ngx_dynamic_upstream_op_t *op,
    ngx_upstream_srv_conf_t *conf)
{
    ngx_dynamic_upstream_srv_conf_t *ucscf;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM) {
        conf->stream = ngx_stream_dynamic_upstream_get(op, conf);
        if (conf->stream != NULL) {
            ucscf = ngx_dynamic_upstream_get_conf(conf->stream);
            if (ucscf->interval != NGX_CONF_UNSET_MSEC)
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;
            if (ucscf->ipv6 == 1)
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;
            return NGX_OK;
        }
        return NGX_ERROR;
    }

    conf->http = ngx_http_dynamic_upstream_get(op, conf);
    if (conf->http != NULL) {
        ucscf = ngx_dynamic_upstream_get_conf(conf->http);
        if (ucscf->interval != NGX_CONF_UNSET_MSEC)
            op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;
        if (ucscf->ipv6 == 1)
            op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_upstream_srv_conf_t *conf)
{
    ngx_upstream_rr_peers_t  peers;

    if (conf->http != NULL)
        peers.http = (ngx_http_upstream_rr_peers_t *) conf->peers;
    else
        peers.stream = (ngx_stream_upstream_rr_peers_t *) conf->peers;

    return ngx_dynamic_upstream_op_impl(log, op, conf->shpool, &peers);
}


extern "C" ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_upstream_srv_conf_t conf;
    if (uscf->shm_zone == NULL) {
        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        op->err = "only for upstream with 'zone'";
        return NGX_ERROR;
    }
    ngx_memzero(&conf, sizeof(ngx_upstream_srv_conf_t));
    conf.http = uscf;
    conf.shpool = (ngx_slab_pool_t *) uscf->shm_zone->shm.addr;
    conf.peers = uscf->peer.data;
    return ngx_dynamic_upstream_op(log, op, &conf);
}


extern "C" ngx_int_t
ngx_dynamic_upstream_stream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_upstream_srv_conf_t conf;
    if (uscf->shm_zone == NULL) {
        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        op->err = "only for upstream with 'zone'";
        return NGX_ERROR;
    }
    ngx_memzero(&conf, sizeof(ngx_upstream_srv_conf_t));
    conf.stream = uscf;
    conf.shpool = (ngx_slab_pool_t *) uscf->shm_zone->shm.addr;
    conf.peers = uscf->peer.data;
    return ngx_dynamic_upstream_op(log, op, &conf);
}


extern ngx_int_t
is_reserved_addr(ngx_str_t *addr);


template <class PeersT, class PeerT> static void
ngx_dynamic_upstream_response_impl(PeersT *peers,
    ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    PeerT   *peer;
    PeersT  *backup = peers->next;
    u_char  *last = b->last + size;

    ngx_upstream_rr_peers_rlock<PeersT> rlock(peers);

    for (; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {

            if (is_reserved_addr(&peer->name))
                continue;
            
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
ngx_dynamic_upstream_response(ngx_upstream_srv_conf_t *conf,
    ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    if (conf->http != NULL) {
        ngx_dynamic_upstream_response_impl
            <ngx_http_upstream_rr_peers_t, ngx_http_upstream_rr_peer_t>
                ((ngx_http_upstream_rr_peers_t *) conf->http->peer.data,
                    b, size, verbose);
        return;
    }

    ngx_dynamic_upstream_response_impl
        <ngx_stream_upstream_rr_peers_t, ngx_stream_upstream_rr_peer_t>
            ((ngx_stream_upstream_rr_peers_t *) conf->stream->peer.data,
                b, size, verbose);
}


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r)
{
    ngx_int_t                       rc = NGX_ERROR;
    ngx_chain_t                     out;
    ngx_dynamic_upstream_op_t       op;
    ngx_buf_t                      *b;
    ngx_upstream_srv_conf_t         conf;

    ngx_memzero(&conf, sizeof(ngx_upstream_srv_conf_t));

    if (r->method != NGX_HTTP_GET) {
        op.err = "only GET allowed";
        op.status = NGX_HTTP_NOT_ALLOWED;
        goto resp;
    }

    if ((rc = ngx_http_discard_request_body(r)) != NGX_OK)
        return rc;

    if ((rc = ngx_dynamic_upstream_build_op(r, &op)) != NGX_OK)
        goto resp;

    if ((rc = ngx_dynamic_upstream_get_conf(&op, &conf)) == NGX_ERROR) {
        op.err = "upstream is not found";
        op.status = NGX_HTTP_NOT_FOUND;
        goto resp;
    }

    rc = ngx_dynamic_upstream_op(r->connection->log, &op, &conf);

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
        ngx_dynamic_upstream_response(&conf, b, size, op.verbose);
    else {
        if (op.status == NGX_HTTP_INTERNAL_SERVER_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, op.err);
        }
        b->last = ngx_snprintf(b->last, size, op.err);
    }

    r->headers_out.content_type = text;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

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
        ngx_palloc(cf->pool, sizeof(ngx_dynamic_upstream_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->interval = NGX_CONF_UNSET_MSEC;
    conf->last = 0;
    conf->ipv6 = NGX_CONF_UNSET;

    return conf;
}


static ngx_http_upstream_main_conf_t *
ngx_dynamic_upstream_loop_get_main_conf(ngx_http_upstream_main_conf_t *)
{
    return (ngx_http_upstream_main_conf_t *)
        ngx_http_cycle_get_module_main_conf(ngx_cycle,
            ngx_http_upstream_module);
}


static ngx_stream_upstream_main_conf_t *
ngx_dynamic_upstream_loop_get_main_conf(ngx_stream_upstream_main_conf_t *)
{
    return (ngx_stream_upstream_main_conf_t *)
        ngx_stream_cycle_get_module_main_conf(ngx_cycle,
            ngx_stream_upstream_module);
}


static void
ngx_dynamic_upstream_loop_conf_cb(ngx_http_upstream_srv_conf_t *uscf,
    ngx_upstream_srv_conf_t *conf, ngx_dynamic_upstream_op_t *op)
{
    conf->http = uscf;
    op->op_param &= ~NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM;
}


static void
ngx_dynamic_upstream_loop_conf_cb(ngx_stream_upstream_srv_conf_t *uscf,
    ngx_upstream_srv_conf_t *conf, ngx_dynamic_upstream_op_t *op)
{
    conf->stream = uscf;
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM;
}


static ngx_dynamic_upstream_srv_conf_t *
ngx_dynamic_upstream_get_conf(ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_dynamic_upstream_srv_conf_t *ucscf =
        (ngx_dynamic_upstream_srv_conf_t *)
            ngx_http_conf_upstream_srv_conf(uscf,
                ngx_http_dynamic_upstream_module);
    return ucscf;
}


static ngx_dynamic_upstream_srv_conf_t *
ngx_dynamic_upstream_get_conf(ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_dynamic_upstream_srv_conf_t *ucscf =
        (ngx_dynamic_upstream_srv_conf_t *)
            ngx_stream_conf_upstream_srv_conf(uscf,
                ngx_stream_dynamic_upstream_module);
    return ucscf;
}


template <class M, class S> void
ngx_dynamic_upstream_loop()
{
    M                               *umcf = NULL;
    S                              **uscf = NULL;
    ngx_upstream_srv_conf_t          conf;
    ngx_dynamic_upstream_op_t        op;
    ngx_uint_t                       j;
    ngx_dynamic_upstream_srv_conf_t *ucscf;
    time_t                           now = 0;

    umcf = ngx_dynamic_upstream_loop_get_main_conf(umcf);
    if (umcf == NULL)
        return;

    uscf = (S **) umcf->upstreams.elts;
    if (uscf == NULL)
        return;

    for (j = 0; j < umcf->upstreams.nelts; j++) {
        if (uscf[j]->shm_zone == NULL)
            continue;

        ucscf = ngx_dynamic_upstream_get_conf(uscf[j]);
        if (ucscf == NULL || ucscf->interval == NGX_CONF_UNSET_MSEC)
            continue;

        time(&now);

        if (ucscf->last + (time_t) ucscf->interval / 1000 > now)
            continue;

        ucscf->last = now;

        ngx_memzero(&op, sizeof(ngx_dynamic_upstream_op_t));

        conf.shpool = (ngx_slab_pool_t *) uscf[j]->shm_zone->shm.addr;
        conf.peers = uscf[j]->peer.data;

        op.op = NGX_DYNAMIC_UPSTEAM_OP_SYNC;
        op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;
        if (ucscf->ipv6 == 1)
            op.op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;
        op.err = "unexpected";
        op.status = NGX_HTTP_OK;

        ngx_dynamic_upstream_loop_conf_cb(uscf[j], &conf, &op);

        if (ngx_dynamic_upstream_op(ngx_cycle->log, &op, &conf) == NGX_OK) {
            ngx_time_update();
            ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                          "DNS dynamic resolver: %V synced", &uscf[j]->host);
        } else if (op.status == NGX_HTTP_INTERNAL_SERVER_ERROR) {
            ngx_time_update();
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, op.err);
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
    if (ngx_worker == 0)
        if (pthread_create((pthread_t *) &DNS_sync_thr, NULL,
            ngx_http_dynamic_upstream_thread, NULL) != 0) {
            ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                          "errno=%d, %s", errno, strerror(errno));
            return NGX_ERROR;
        }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "DNS dynamic resolver thread started");

    return NGX_OK;
}


static void
ngx_http_dynamic_upstream_exit_worker(ngx_cycle_t *cycle)
{
    pthread_t saved = DNS_sync_thr;
    if (DNS_sync_thr) {
        DNS_sync_thr = 0;
        pthread_join(saved, NULL);
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "DNS dynamic resolver thread stopped");
    }
}
