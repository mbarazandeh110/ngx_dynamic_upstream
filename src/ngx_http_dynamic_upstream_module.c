#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"


static ngx_http_upstream_srv_conf_t *
ngx_http_dynamic_upstream_get_zone(ngx_http_request_t *r,
    ngx_dynamic_upstream_op_t *op);


static ngx_stream_upstream_srv_conf_t *
ngx_stream_dynamic_upstream_get_zone(ngx_dynamic_upstream_op_t *op);


static ngx_int_t
ngx_http_dynamic_upstream_response(ngx_http_upstream_rr_peers_t *peers,
    ngx_buf_t *b, size_t size, ngx_int_t verbose);


static ngx_int_t
ngx_stream_dynamic_upstream_response(ngx_stream_upstream_rr_peers_t *peers,
    ngx_buf_t *b, size_t size, ngx_int_t verbose);


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r);


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


static ngx_http_upstream_srv_conf_t *
ngx_http_dynamic_upstream_get_zone(ngx_http_request_t *r,
    ngx_dynamic_upstream_op_t *op)
{
    ngx_uint_t                      i;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf  = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (umcf == NULL) {
        return NULL;
    }
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        if (uscf->shm_zone != NULL &&
            uscf->shm_zone->shm.name.len == op->upstream.len &&
            ngx_strncmp(uscf->shm_zone->shm.name.data, op->upstream.data,
                        op->upstream.len) == 0)
        {
            return uscf;
        }
    }

    return NULL;
}


static ngx_stream_upstream_srv_conf_t *
ngx_stream_dynamic_upstream_get_zone(ngx_dynamic_upstream_op_t *op)
{
    ngx_uint_t                      i;
    ngx_stream_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_stream_upstream_main_conf_t  *umcf;

    umcf  = ngx_stream_cycle_get_module_main_conf(ngx_cycle,
        ngx_stream_upstream_module);
    if (umcf == NULL) {
        return NULL;
    }
    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {
        uscf = uscfp[i];
        if (uscf->shm_zone != NULL &&
            uscf->shm_zone->shm.name.len == op->upstream.len &&
            ngx_strncmp(uscf->shm_zone->shm.name.data, op->upstream.data,
                        op->upstream.len) == 0)
        {
            return uscf;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_http_dynamic_upstream_response(ngx_http_upstream_rr_peers_t *peers,
    ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    ngx_http_upstream_rr_peer_t  *peer;
    ngx_http_upstream_rr_peers_t *primary, *backup;
    u_char                       *last;

    primary = peers;

    ngx_http_upstream_rr_peers_rlock(primary);

    backup = primary->next;

    last = b->last + size;

    for (; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {

            if (verbose) {
                b->last = ngx_snprintf(b->last, last - b->last,
                    "server %V weight=%d max_fails=%d fail_timeout=%d"
#if defined(nginx_version) && (nginx_version >= 1011005)
                    " max_conns=%d"
#endif
                    " conns=%d",
                    &peer->name, peer->weight, peer->max_fails,
                    peer->fail_timeout,
#if defined(nginx_version) && (nginx_version >= 1011005)
                    peer->max_conns,
#endif
                    peer->conns);

            } else {
                b->last = ngx_snprintf(b->last, last - b->last,
                                       "server %V", &peer->name);
            }

            b->last = peer->down
                ? ngx_snprintf(b->last, last - b->last, " down")
                : ngx_snprintf(b->last, last - b->last, "");
            b->last = peers == backup
                ? ngx_snprintf(b->last, last - b->last, " backup;\n")
                : ngx_snprintf(b->last, last - b->last, ";\n");
        }
    }

    ngx_http_upstream_rr_peers_unlock(primary);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_dynamic_upstream_response(ngx_stream_upstream_rr_peers_t *peers,
    ngx_buf_t *b, size_t size, ngx_int_t verbose)
{
    ngx_stream_upstream_rr_peer_t  *peer;
    ngx_stream_upstream_rr_peers_t *primary, *backup;
    u_char                         *last;

    primary = peers;

    ngx_http_upstream_rr_peers_rlock(primary);

    backup = primary->next;

    last = b->last + size;

    for (; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {

            if (verbose) {
                b->last = ngx_snprintf(b->last, last - b->last,
                    "server %V weight=%d max_fails=%d fail_timeout=%d"
#if defined(nginx_version) && (nginx_version >= 1011005)
                    " max_conns=%d"
#endif
                    " conns=%d",
                    &peer->name, peer->weight, peer->max_fails,
                    peer->fail_timeout,
#if defined(nginx_version) && (nginx_version >= 1011005)
                    peer->max_conns,
#endif
                    peer->conns);
            } else {
                b->last = ngx_snprintf(b->last, last - b->last,
                                       "server %V", &peer->name);
            }

            b->last = peer->down
                ? ngx_snprintf(b->last, last - b->last, " down")
                : ngx_snprintf(b->last, last - b->last, "");
            b->last = peers == backup
                ? ngx_snprintf(b->last, last - b->last, " backup;\n")
                : ngx_snprintf(b->last, last - b->last, ";\n");
        }
    }

    ngx_http_upstream_rr_peers_unlock(primary);

    return NGX_OK;
}


typedef struct {
    ngx_http_upstream_srv_conf_t *http;
    ngx_stream_upstream_srv_conf_t *stream;
} ngx_upstream_srv_conf_t;


static ngx_int_t
ngx_dynamic_upstream_handler(ngx_http_request_t *r)
{
    size_t                          size;
    ngx_int_t                       rc;
    ngx_chain_t                     out;
    ngx_dynamic_upstream_op_t       op;
    ngx_buf_t                      *b;
    ngx_upstream_srv_conf_t         uscf;

    ngx_memzero(&uscf, sizeof(ngx_upstream_srv_conf_t));

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
    
    r->headers_out.content_type_len = sizeof("text/plain") - 1;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;

        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    rc = ngx_dynamic_upstream_build_op(r, &op);
    if (rc != NGX_OK) {
        if (op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return op.status;
    }

    if (op.op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM) {
        uscf.stream = ngx_stream_dynamic_upstream_get_zone(&op);
    } else {
        uscf.http = ngx_http_dynamic_upstream_get_zone(r, &op);
    }

    if (uscf.stream == NULL && uscf.http == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "upstream is not found. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return NGX_HTTP_NOT_FOUND;
    }

    if (uscf.stream) {
        rc = ngx_dynamic_upstream_stream_op(r->connection->log, &op,
                                            uscf.stream);
        size = uscf.stream->shm_zone->shm.size;
    } else {
        rc = ngx_dynamic_upstream_op(r->connection->log, &op, uscf.http);
        size = uscf.http->shm_zone->shm.size;
    }

    if (rc != NGX_OK) {
        if (op.status == NGX_HTTP_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return op.status;
    }


    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    rc = uscf.stream
        ? ngx_stream_dynamic_upstream_response(uscf.stream->peer.data, b,
                                               size, op.verbose)
        : ngx_http_dynamic_upstream_response(uscf.http->peer.data, b,
                                             size, op.verbose);

    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "failed to create a response. %s:%d",
                      __FUNCTION__,
                      __LINE__);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;

    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_dynamic_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_dynamic_upstream_handler;

    return NGX_CONF_OK;
}


ngx_int_t
ngx_dynamic_upstream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_http_upstream_srv_conf_t *uscf)
{
    ngx_upstream_rr_peers_t  peers;
    ngx_slab_pool_t         *slab_pool = NULL;

    if (uscf->shm_zone) {
        slab_pool = (ngx_slab_pool_t *) uscf->shm_zone->shm.addr;
    }

    peers.http = uscf->peer.data;

    return ngx_dynamic_upstream_op_impl(log, op, slab_pool, &peers);
}


ngx_int_t
ngx_dynamic_upstream_stream_op(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_stream_upstream_srv_conf_t *uscf)
{
    ngx_upstream_rr_peers_t  peers;
    ngx_slab_pool_t         *slab_pool = NULL;

    if (uscf->shm_zone) {
        slab_pool = (ngx_slab_pool_t *) uscf->shm_zone->shm.addr;
    }

    peers.stream = uscf->peer.data;

    return ngx_dynamic_upstream_op_impl(log, op, slab_pool, &peers);
}
