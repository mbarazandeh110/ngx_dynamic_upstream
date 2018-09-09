extern "C" {

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

}

#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"


static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_dynamic_upstream_commands[] = {
    {
        ngx_string("dynamic_upstream"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_dynamic_upstream,
        0,
        0,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t ngx_http_dynamic_upstream_module_ctx = {
    NULL,                                       /* preconfiguration  */
    NULL,                                       /* postconfiguration */

    NULL,                                       /* create main       */
    NULL,                                       /* init main         */

    NULL,                                       /* create server     */
    NULL,                                       /* merge server      */

    NULL,                                       /* create location   */
    NULL                                        /* merge location    */
};


ngx_module_t ngx_http_dynamic_upstream_module = {
    NGX_MODULE_V1,
    &ngx_http_dynamic_upstream_module_ctx,     /* module context    */
    ngx_http_dynamic_upstream_commands,        /* module directives */
    NGX_HTTP_MODULE,                           /* module type       */
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
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM) {
        conf->stream = ngx_stream_dynamic_upstream_get(op, conf);
        return conf->stream != NULL ? NGX_OK : NGX_ERROR;
    }

    conf->http = ngx_http_dynamic_upstream_get(op, conf);
    return conf->http != NULL ? NGX_OK : NGX_ERROR;
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
