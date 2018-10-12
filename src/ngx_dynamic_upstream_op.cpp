/*
 * Copyright (c) 2015 Tatsuhiko Kubo (cubicdaiya@gmail.com>)
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

extern "C" {

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_inet.h>


#include <assert.h>

}

#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"


static const ngx_str_t ngx_dynamic_upstream_params[] = {
    ngx_string("arg_upstream"),
    ngx_string("arg_verbose"),
    ngx_string("arg_add"),
    ngx_string("arg_remove"),
    ngx_string("arg_backup"),
    ngx_string("arg_server"),
    ngx_string("arg_weight"),
    ngx_string("arg_max_fails"),

#if defined(nginx_version) && (nginx_version >= 1011005)
    ngx_string("arg_max_conns"),
#endif

    ngx_string("arg_fail_timeout"),
    ngx_string("arg_up"),
    ngx_string("arg_down"),
    ngx_string("arg_stream"),
    ngx_string("arg_ipv6")
};


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_add(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, PeersT *primary);


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_sync(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary);


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_del(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary);


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_update(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, PeersT *primary);


template <class T> T*
ngx_shm_calloc(ngx_slab_pool_t *shpool, size_t size = 0)
{
    return (T*) ngx_slab_calloc(shpool, size == 0 ? sizeof(T) : size);
}


template <class T> T*
ngx_pool_pcalloc(ngx_pool_t *pool, size_t size)
{
    return (T*) ngx_pcalloc(pool, size);
}


template <class T> T*
ngx_pool_pnalloc(ngx_pool_t *pool, size_t size)
{
    return (T*) ngx_pnalloc(pool, size);
}


ngx_int_t
ngx_dynamic_upstream_build_op(ngx_http_request_t *r,
    ngx_dynamic_upstream_op_t *op)
{
    ngx_uint_t                  i;
    size_t                      args_size;
    u_char                     *low;
    ngx_uint_t                  key;
    ngx_str_t                  *args;
    ngx_http_variable_value_t  *var;

    ngx_memzero(op, sizeof(ngx_dynamic_upstream_op_t));

    op->err = "unexpected";
    op->status = NGX_HTTP_OK;

    ngx_str_null(&op->upstream);
    ngx_str_null(&op->server);

    op->weight       = 1;
    op->max_fails    = 1;
    op->fail_timeout = 10;

    args = (ngx_str_t *) &ngx_dynamic_upstream_params;
    args_size = sizeof(ngx_dynamic_upstream_params) / sizeof(ngx_str_t);

    for (i = 0; i < args_size; i++) {
        low = ngx_pool_pnalloc<u_char>(r->pool, args[i].len);
        if (low == NULL) {
            op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            op->err = "no memory";
            return NGX_ERROR;
        }

        key = ngx_hash_strlow(low, args[i].data, args[i].len);
        var = ngx_http_get_variable(r, &args[i], key);

        if (!var->not_found) {
            if (ngx_strcmp("arg_upstream", args[i].data) == 0) {
                op->upstream.data = var->data;
                op->upstream.len = var->len;

            } else if (ngx_strcmp("arg_verbose", args[i].data) == 0) {
                op->verbose = 1;

            } else if (ngx_strcmp("arg_add", args[i].data) == 0) {
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_ADD;

            } else if (ngx_strcmp("arg_remove", args[i].data) == 0) {
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_REMOVE;

            } else if (ngx_strcmp("arg_backup", args[i].data) == 0) {
                op->backup = 1;

            } else if (ngx_strcmp("arg_server", args[i].data) == 0) {
                op->server.data = var->data;
                op->server.len = var->len;

            } else if (ngx_strcmp("arg_weight", args[i].data) == 0) {
                op->weight = ngx_atoi(var->data, var->len);
                if (op->weight == NGX_ERROR) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    op->err = "weight is not number";
                    return NGX_ERROR;
                }
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT;
                op->verbose = 1;

            } else if (ngx_strcmp("arg_max_fails", args[i].data) == 0) {
                op->max_fails = ngx_atoi(var->data, var->len);
                if (op->max_fails == NGX_ERROR) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    op->err = "max_fails is not number";
                    return NGX_ERROR;
                }
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS;
                op->verbose = 1;

            }

#if defined(nginx_version) && (nginx_version >= 1011005)
             else if (ngx_strcmp("arg_max_conns", args[i].data) == 0) {
                op->max_conns = ngx_atoi(var->data, var->len);
                if (op->max_conns == NGX_ERROR) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    op->err = "max_conns is not number";
                    return NGX_ERROR;
                }
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS;
                op->verbose = 1;
            }
#endif

            else if (ngx_strcmp("arg_fail_timeout", args[i].data) == 0) {
                op->fail_timeout = ngx_atoi(var->data, var->len);
                if (op->fail_timeout == NGX_ERROR) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    op->err = "fail_timeout is not number";
                    return NGX_ERROR;
                }
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT;
                op->verbose = 1;

            } else if (ngx_strcmp("arg_up", args[i].data) == 0) {
                op->up = 1;
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP;
                op->verbose = 1;

            } else if (ngx_strcmp("arg_down", args[i].data) == 0) {
                op->down = 1;
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN;
                op->verbose = 1;

            } else if (ngx_strcmp("arg_stream", args[i].data) == 0) {
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM;

            } else if (ngx_strcmp("arg_ipv6", args[i].data) == 0) {
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;

            }
        }
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


ngx_int_t
ngx_dynamic_upstream_op_impl(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, ngx_upstream_rr_peers_t *peers)
{
    ngx_int_t rc = NGX_OK;

    switch (op->op) {
    case NGX_DYNAMIC_UPSTEAM_OP_ADD:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
           ? ngx_dynamic_upstream_op_add<ngx_stream_upstream_rr_peers_t,
                                         ngx_stream_upstream_rr_peer_t>
                (log, op, shpool, peers->stream)
           : ngx_dynamic_upstream_op_add<ngx_http_upstream_rr_peers_t,
                                         ngx_http_upstream_rr_peer_t>
                (log, op, shpool, peers->http);
        break;

    case NGX_DYNAMIC_UPSTEAM_OP_REMOVE:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
            ? ngx_dynamic_upstream_op_del<ngx_stream_upstream_rr_peers_t,
                                          ngx_stream_upstream_rr_peer_t>
                (log, op, shpool, peers->stream)
            : ngx_dynamic_upstream_op_del<ngx_http_upstream_rr_peers_t,
                                          ngx_http_upstream_rr_peer_t>
                (log, op, shpool, peers->http);
        break;

    case NGX_DYNAMIC_UPSTEAM_OP_SYNC:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
            ? ngx_dynamic_upstream_op_sync<ngx_stream_upstream_rr_peers_t,
                                           ngx_stream_upstream_rr_peer_t>
                (log, op, shpool, peers->stream)
            : ngx_dynamic_upstream_op_sync<ngx_http_upstream_rr_peers_t,
                                           ngx_http_upstream_rr_peer_t>
                (log, op, shpool, peers->http);
        break;

    case NGX_DYNAMIC_UPSTEAM_OP_PARAM:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
            ? ngx_dynamic_upstream_op_update<ngx_stream_upstream_rr_peers_t,
                                         ngx_stream_upstream_rr_peer_t>
                (log, op, peers->stream)
            : ngx_dynamic_upstream_op_update<ngx_http_upstream_rr_peers_t,
                                             ngx_http_upstream_rr_peer_t>
                (log, op, peers->http);
        break;

    case NGX_DYNAMIC_UPSTEAM_OP_LIST:
    default:
        rc = NGX_OK;
        break;
    }

    return rc;
}


static const ngx_str_t
no_resolve_addr = ngx_string("0.0.0.0:1");

static const ngx_str_t
resolve_addr    = ngx_string("0.0.0.0:2");


ngx_int_t
is_reserved_addr(ngx_str_t *addr)
{
    return addr->len == resolve_addr.len &&
           ngx_memcmp(addr->data, resolve_addr.data, resolve_addr.len - 2) == 0;
}

static ngx_int_t
ngx_dynamic_upstream_parse_url(ngx_url_t *u,
    ngx_pool_t *pool,
    ngx_dynamic_upstream_op_t *op, unsigned no_resolve = 1)
{
    ngx_memzero(u, sizeof(ngx_url_t));

    u->url = op->server;
    u->default_port = 80;
    u->no_resolve = no_resolve;

    if (ngx_parse_url(pool, u) != NGX_OK) {
        if (u->err)
            op->err = u->err;
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    if (u->naddrs == 0) {
        if (no_resolve) {
            u->url = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE
                   ? resolve_addr : no_resolve_addr;
            if (ngx_parse_url(pool, u) != NGX_OK) {
                if (u->err)
                    op->err = u->err;
                op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_ERROR;
            }
            u->url = op->server;
            return NGX_AGAIN;
        } else {
            op->err = "failed to resolve";
            op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_add_peer(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary, ngx_url_t *u, int i)
{
    PeerT       *peer, *last = NULL, *npeer;
    PeersT      *peers, *backup = primary->next;
    ngx_uint_t   j = 0;

    if (u->addrs[i].name.data[0] == '[' &&
        !(op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6)) {
        op->status = NGX_HTTP_NOT_MODIFIED;
        return NGX_OK;
    }

    op->status = NGX_HTTP_OK;

    for (peers = primary; peers && j < 2; peers = peers->next, j++) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if (u->addrs[i].name.len == peer->name.len &&
                ngx_strncmp(u->addrs[i].name.data, peer->name.data,
                            peer->name.len) == 0) {
                op->status = NGX_HTTP_NOT_MODIFIED;
                return NGX_OK;
            }
            if ( (op->backup == 0 && peers == primary) ||
                 (op->backup == 1 && peers == backup) )
                last = peer;
        }
    }

    if (op->backup) {
        if (backup == NULL) {
            assert(last == NULL);
            backup = ngx_shm_calloc<PeersT>(shpool);
            if (backup == NULL) {
                op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                op->err = "no shared memory";
                return NGX_ERROR;
            }
            backup->shpool = primary->shpool;
            backup->name = primary->name;
        }

        peers = backup;
    } else
        peers = primary;

    npeer = ngx_shm_calloc<PeerT>(shpool);
    if (npeer == NULL)
        goto fail;

    npeer->server.data = ngx_shm_calloc<u_char>(shpool, u->url.len + 1);
    npeer->name.data = ngx_shm_calloc<u_char>(shpool, u->addrs[i].name.len + 1);
    npeer->sockaddr = ngx_shm_calloc<sockaddr>(shpool, u->addrs[i].socklen);

    if (npeer->server.data == NULL)
        goto fail;

    if (npeer->name.data == NULL)
        goto fail;

    if (npeer->sockaddr == NULL)
        goto fail;

    npeer->name.len = u->addrs[i].name.len;
    ngx_memcpy(npeer->name.data, u->addrs[i].name.data, npeer->name.len);
 
    npeer->server.len = u->url.len;
    ngx_memcpy(npeer->server.data, u->url.data, npeer->server.len);

    npeer->socklen = u->addrs[i].socklen;
    ngx_memcpy(npeer->sockaddr, u->addrs[i].sockaddr, npeer->socklen);

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT) {
        npeer->weight = op->weight;
        npeer->effective_weight = op->weight;
        npeer->current_weight = 0;
    } else {
        npeer->weight = 1;
        npeer->effective_weight = 1;
        npeer->current_weight = 0;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS)
        npeer->max_fails = op->max_fails;
    else
        npeer->max_fails = 1;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT)
        npeer->fail_timeout = op->fail_timeout;
    else
        npeer->fail_timeout = 10;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN)
        npeer->down = op->down;

    if (last == NULL)
        peers->peer = npeer;
    else
        last->next = npeer;

    peers->total_weight += npeer->weight;
    peers->single = (peers->number == 0);
    peers->number++;
    peers->weighted = (peers->total_weight != peers->number);

    if (backup != NULL && primary->next == NULL)
        primary->next = backup;

    if (!is_reserved_addr(&u->addrs[i].name))
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%V: added server %V peer %V",
                      &op->upstream, &u->url, &u->addrs[i].name);

    return NGX_OK;

fail:

    if (npeer != NULL) {
        if (npeer->server.data != NULL)
            ngx_slab_free(shpool, npeer->server.data);
        if (npeer->name.data != NULL)
            ngx_slab_free(shpool, npeer->name.data);
        if (npeer->sockaddr != NULL)
            ngx_slab_free(shpool, npeer->sockaddr);
        ngx_slab_free(shpool, npeer);
    }

    if (backup != NULL && primary->next == NULL)
        ngx_slab_free(shpool, backup);

    op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    op->err = "no shared memory";

    return NGX_ERROR;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_add_impl(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary, ngx_url_t *u)
{
    unsigned   i;
    int        resolve = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;
    unsigned   count = 0;

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary);

    for (i = 0; i < u->naddrs; ++i) {
        if (ngx_dynamic_upstream_op_add_peer<PeersT, PeerT>(log, op, shpool,
                primary, u, i) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (op->status == NGX_HTTP_OK)
           count++;

        if (!resolve)
            break;
    }

    op->status = count != 0 ? NGX_HTTP_OK : NGX_HTTP_NOT_MODIFIED;

    return NGX_OK;
}


struct ngx_pool_auto {
    ngx_pool_t   *pool;

    ngx_pool_auto(ngx_log_t *log)
        : pool(ngx_create_pool(ngx_pagesize - 1, log))
    {}

    ~ngx_pool_auto()
    {
        if (pool != NULL)
            ngx_destroy_pool(pool);
    }
};


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_add(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary)
{
    ngx_url_t  u;
    ngx_int_t  rc;

    ngx_pool_auto guard(log);

    if (guard.pool == NULL) {
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        op->err = "no memory";
        return NGX_ERROR;
    }

    if ((rc = ngx_dynamic_upstream_parse_url(&u, guard.pool, op)) == NGX_ERROR)
        return NGX_ERROR;

    if (rc == NGX_AGAIN) {
        if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE) {
            op->down = 1;
            op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN;
        } else {
            op->err = "domain names are supported only for upstreams "
                      "with 'dns_update' directive";
            op->status = NGX_HTTP_BAD_REQUEST;
            return NGX_ERROR;
        }
    }

    if (ngx_dynamic_upstream_op_add_impl<PeersT, PeerT>(log, op,
        shpool, primary, &u) == NGX_ERROR)
        return NGX_ERROR;

    if (rc == NGX_AGAIN) {
        op->err = "DNS resolving in progress";
        op->status = NGX_HTTP_PROCESSING;
    }

    return rc;
}


struct ngx_server_s {
    ngx_str_t name;
    ngx_int_t backup;
    ngx_int_t weight;
    ngx_int_t max_fails;

#if defined(nginx_version) && (nginx_version >= 1011005)
    ngx_int_t max_conns;
#endif

    ngx_int_t fail_timeout;
    ngx_int_t down;
    ngx_url_t u;

    ngx_int_t resolve;
};
typedef struct ngx_server_s ngx_server_t;


static ngx_uint_t
ngx_dynamic_upstream_op_server_exist(ngx_array_t *servers,
    ngx_str_t *name)
{
    ngx_server_t   *server = (ngx_server_t *) servers->elts;
    unsigned        j;

    for (j = 0; j < servers->nelts; ++j) {
        if (server[j].name.len == name->len &&
            ngx_strncmp(server[j].name.data, name->data,
                        name->len) == 0) {
            return 1;
        }
    }

    return 0;
}


static ngx_uint_t
ngx_dynamic_upstream_op_peer_exist(ngx_array_t *servers,
    ngx_str_t *name)
{
    ngx_server_t   *server = (ngx_server_t *) servers->elts;
    unsigned        i, j;

    for (j = 0; j < servers->nelts; ++j) {
        for (i = 0; i < server[j].u.naddrs; ++i) {
            if (server[j].u.addrs[i].name.len == name->len &&
                ngx_strncmp(server[j].u.addrs[i].name.data, name->data,
                            name->len) == 0)
                    return 1;
        }
    }

    return 0;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_servers(PeersT *primary,
    ngx_array_t *servers, ngx_pool_t *pool)
{
    PeerT         *peer;
    PeersT        *peers;
    ngx_server_t  *server;
    ngx_uint_t     i = 0;

    ngx_upstream_rr_peers_rlock<PeersT> lock(primary);

    for (peers = primary; peers && i < 2; peers = peers->next, i++) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if (!ngx_dynamic_upstream_op_server_exist(servers, &peer->server)) {
                server = (ngx_server_t *) ngx_array_push(servers);
                if (server == NULL)
                    return NGX_ERROR;

                server->name.data = ngx_pool_pcalloc<u_char>(pool,
                    peer->server.len + 1);
                if (server->name.data == NULL)
                    return NGX_ERROR;

                ngx_memcpy(server->name.data, peer->server.data,
                           peer->server.len);
                server->name.len     = peer->server.len;
                server->backup       = peers == primary->next;
                server->down         = peer->down != 0;
                server->weight       = peer->weight;
                server->max_fails    = peer->max_fails;
                server->fail_timeout = peer->fail_timeout;
#if defined(nginx_version) && (nginx_version >= 1011005)
                server->max_conns    = peer->max_conns;
#endif
                server->resolve      = peer->name.len == resolve_addr.len
                    && ngx_memcmp(peer->name.data, resolve_addr.data,
                                  resolve_addr.len) == 0;
            }
        }
    }

    return NGX_OK;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_sync(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary)
{
    unsigned         i, j;
    int              resolve;
    ngx_server_t    *server;
    PeerT           *peer;
    PeersT          *peers;
    unsigned         count = 0;
    ngx_array_t     *servers;

    resolve = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;

    ngx_pool_auto guard(log);

    if (guard.pool == NULL) {
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        op->err = "no memory";
        return NGX_ERROR;
    }

    servers = ngx_array_create(guard.pool, 100, sizeof(ngx_server_t));
    if (servers == NULL) {
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        op->err = "no memory";
        return NGX_ERROR;
    }

    if (ngx_dynamic_upstream_op_servers<PeersT, PeerT>(primary,
                                                       servers,
                                                       guard.pool)
        == NGX_ERROR)
    {
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        op->err = "no memory";
        return NGX_ERROR;
    }

    server = (ngx_server_t *) servers->elts;

    for (j = 0; j < servers->nelts; ++j) {
        op->server = server[j].name;
        if (ngx_dynamic_upstream_parse_url(&server[j].u, guard.pool,
                                           op, 0) != NGX_OK)
            return NGX_ERROR;
    }

    op->no_lock = 1;

    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT;
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS;
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT;
#if defined(nginx_version) && (nginx_version >= 1011005)
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS;
#endif

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary);

    for (j = 0; j < servers->nelts; ++j) {
        for (i = 0; i < server[j].u.naddrs; ++i) {
            if (server[j].u.addrs[i].name.len == server[j].name.len &&
                ngx_memcmp(server[j].u.addrs[i].name.data, server[j].name.data,
                           server[j].name.len) == 0)
                break;

            op->weight       = server[j].weight;
            op->backup       = server[j].backup;
            op->max_fails    = server[j].max_fails;
        #if defined(nginx_version) && (nginx_version >= 1011005)
            op->max_conns    = server[j].max_conns;
        #endif
            op->fail_timeout = server[j].fail_timeout;

            if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP) {

                op->op_param &= ~NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN;
                op->down = 0;
            } else if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN) {

                op->op_param &= ~NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP;
                op->down = 1;
            }

            if (!server[j].resolve && server[j].down) {

                op->op_param &= ~NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN;
                op->down = 1;
            }

            if (ngx_dynamic_upstream_op_add_peer<PeersT, PeerT>
                    (log, op, shpool, primary, &server[j].u, i) == NGX_ERROR)
                return NGX_ERROR;

            if (op->status == NGX_HTTP_OK)
                count++;

            if (resolve | server[j].resolve)
                continue;

            break;
        }
    }

    i = 0;

    for (peers = primary; peers && i < 2; peers = peers->next, i++) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((peer->name.data[0] == '[' &&
                !(op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6)) ||
                !ngx_dynamic_upstream_op_peer_exist(servers, &peer->name))
            {
                op->server = peer->name;
                if (ngx_dynamic_upstream_op_del<PeersT, PeerT>
                       (log, op, shpool, primary) == NGX_ERROR)
                    return NGX_ERROR;

                count++;
            }
        }
    }

    op->status = count != 0 ? NGX_HTTP_OK : NGX_HTTP_NOT_MODIFIED;

    return NGX_OK;
}


typedef ngx_int_t (*cleanup_t) (ngx_slab_pool_t *shpool, void *peer);


typedef struct {
    ngx_slab_pool_t *shpool;
    void            *peer;
    cleanup_t        free;
} ngx_dynamic_cleanup_t;


static ngx_connection_t dumb_conn;
static ngx_event_t      cleanup_ev;


static void
ngx_dynamic_cleanup(ngx_event_t *ev);


static ngx_array_t *trash = NULL;


static ngx_array_t *
ngx_dynamic_trash_init()
{
    trash = ngx_array_create(ngx_cycle->pool, 100,
                             sizeof(ngx_dynamic_cleanup_t));

    if (trash) {
        ngx_memzero(&cleanup_ev, sizeof(ngx_event_t));
        ngx_memzero(&dumb_conn, sizeof(ngx_connection_t));
        dumb_conn.fd = -1;
        cleanup_ev.handler = ngx_dynamic_cleanup;
        cleanup_ev.data = &dumb_conn;
        cleanup_ev.log = ngx_cycle->log;
        ngx_add_timer(&cleanup_ev, 1000);
    }

    return trash;
}


static void
ngx_dynamic_add_to_trash(ngx_slab_pool_t *shpool, void *peer, cleanup_t cb)
{
    ngx_dynamic_cleanup_t  *p;

    if (trash == NULL && ngx_dynamic_trash_init() == NULL)
        return;

    p = (ngx_dynamic_cleanup_t *) ngx_array_push(trash);

    if (p != NULL) {
        p->shpool = shpool;
        p->peer = peer;
        p->free = cb;
    }
}


static void
ngx_dynamic_cleanup(ngx_event_t *ev)
{
    ngx_dynamic_cleanup_t *elts = (ngx_dynamic_cleanup_t *) trash->elts;
    ngx_uint_t             i, j = 0;

    if (trash->nelts == 0)
        goto settimer;

    for (i = 0; i < trash->nelts; i++)
        if (elts[i].free(elts[i].shpool, elts[i].peer) == -1)
            elts[j++] = elts[i];

    trash->nelts = j;

settimer:

    if (ngx_exiting || ngx_terminate || ngx_quit)
        return;

    ngx_add_timer(ev, 1000);
}


template <class PeerT> struct FreeFunctor {
  static ngx_int_t free(ngx_slab_pool_t *shpool, void *p);

private:

  static ngx_int_t
  do_free(ngx_slab_pool_t *shpool, PeerT *peer)
  {
      ngx_upstream_rr_peer_lock<PeerT> lock(peer);

      if (peer->conns == 0) {
          ngx_slab_free(shpool, peer->server.data);
          ngx_slab_free(shpool, peer->name.data);
          ngx_slab_free(shpool, peer->sockaddr);

          lock.release();

          ngx_slab_free(shpool, peer);

          return 0;
      }

      return -1;
  }
};


template <> ngx_int_t
FreeFunctor<ngx_http_upstream_rr_peer_t>::free
    (ngx_slab_pool_t *shpool, void *p)
{
    return FreeFunctor<ngx_http_upstream_rr_peer_t>::do_free(shpool,
        (ngx_http_upstream_rr_peer_t *) p);
}


template <> ngx_int_t
FreeFunctor<ngx_stream_upstream_rr_peer_t>::free
    (ngx_slab_pool_t *shpool, void *p)
{
    return FreeFunctor<ngx_stream_upstream_rr_peer_t>::do_free(shpool,
        (ngx_stream_upstream_rr_peer_t *) p);
}


template <class PeerT> static void
ngx_dynamic_upstream_op_free_peer(ngx_slab_pool_t *shpool, PeerT *peer)
{
    if (FreeFunctor<PeerT>::free(shpool, peer) == -1)
        ngx_dynamic_add_to_trash(shpool, peer,
                                 &FreeFunctor<PeerT>::free);
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_del(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, PeersT *primary)
{
    PeerT       *peer, *deleted, *prev;
    PeersT      *peers, *backup = primary->next;
    ngx_int_t    count = 0;
    ngx_uint_t   i = 0;

    op->status = NGX_HTTP_OK;

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary, op->no_lock);

again:

    deleted = NULL;

    for (peers = primary; peers && i < 2; peers = peers->next, i++) {
        prev = NULL;
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((op->server.len == peer->server.len &&
                 ngx_strncmp(op->server.data, peer->server.data,
                             peer->server.len) == 0) ||
                (op->server.len == peer->name.len &&
                 ngx_strncmp(op->server.data, peer->name.data,
                             peer->name.len) == 0))
            {
                if (peers == primary && peers->number == 1) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    return NGX_ERROR;
                }
                deleted = peer;
                peer = peer->next;
                count++;
                goto del;
            }
            prev = peer;
        }
    }

del:

    /* not found */
    if (deleted == NULL) {
        if (count == 0)
            op->status = NGX_HTTP_NOT_MODIFIED;
        return NGX_OK;
    }

    /* found head */
    if (prev == NULL) {
        peers->peer = peer;
        goto ok;
    }

    /* found tail */
    if (peer == NULL) {
        prev->next = NULL;
        goto ok;
    }

    /* found inside */
    prev->next = peer;

 ok:

    peers->number--;
    peers->total_weight -= deleted->weight;
    peers->single = peers->number == 1;
    peers->weighted = peers->total_weight != peers->number;

    if (peers->number == 0) {
        assert(peers == backup);
        primary->next = NULL;
        ngx_slab_free(shpool, backup);
    }

    if (!is_reserved_addr(&deleted->name))
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%V: removed server %V peer %V",
                      &op->upstream, &deleted->server, &deleted->name);

    ngx_dynamic_upstream_op_free_peer<PeerT>(shpool, deleted);

    goto again;
}


template <class PeersT, class PeerT> static void
ngx_dynamic_upstream_op_update_peer(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, PeersT *peers, PeerT *peer)
{
    ngx_upstream_rr_peer_lock<PeerT> lock(peer);

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT) {
        peers->total_weight -= peer->weight;
        peers->total_weight += op->weight;
        peers->weighted = peers->total_weight != peers->number;
        peer->weight = op->weight;
        peer->current_weight = op->weight;
        peer->effective_weight = op->weight;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS)
        peer->max_fails = op->max_fails;

#if defined(nginx_version) && (nginx_version >= 1011005)
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS)
        peer->max_conns = op->max_conns;
#endif

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT)
        peer->fail_timeout = op->fail_timeout;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP) {
        peer->down = 0;
        peer->checked = ngx_time();
        peer->fails = 0;
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%V: up peer %V",
                      &op->upstream, &peer->name);
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN) {
        peer->down = 1;
        peer->checked = ngx_time();
        peer->fails = peer->max_fails;
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%V: down peer %V",
                      &op->upstream, &peer->name);
    }
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_update(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, PeersT *primary)
{
    PeerT     *peer;
    PeersT    *peers;
    unsigned   count = 0;

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary);

    for (peers = primary; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((op->server.len == peer->server.len &&
                 ngx_strncmp(op->server.data, peer->server.data,
                             peer->server.len) == 0) ||
                (op->server.len == peer->name.len &&
                 ngx_strncmp(op->server.data, peer->name.data,
                             peer->server.len) == 0)) {
                ngx_dynamic_upstream_op_update_peer<PeersT, PeerT>(log, op,
                                                                   peers, peer);
                count++;
            }
        }
    }

    if (count == 0) {
        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = "server or peer is not found";
        return NGX_ERROR;
    }

    return NGX_OK;
}
