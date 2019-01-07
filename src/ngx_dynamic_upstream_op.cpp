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


static ngx_str_t
get(ngx_http_request_t *r, const char *arg,
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
    ngx_str_t  v = get(r, arg, op, flag);
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
    return get(r, arg, op, flag).data != NULL;
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

    op->upstream = get(r, "upstream", op);
    if (!op->upstream.data) {

        op->status = NGX_HTTP_BAD_REQUEST;
        op->err = "upstream required";
        return NGX_ERROR;
    }

    op->verbose = get_bool(r, "verbose", op);
    op->backup = get_bool(r, "backup", op);
    op->server = get(r, "server", op);
    op->name = get(r, "peer", op);
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


ngx_int_t
ngx_dynamic_upstream_op_impl(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, ngx_upstream_rr_peers_t *peers)
{
    ngx_int_t rc = NGX_OK;

    op->status = NGX_HTTP_OK;
    op->err = "unexpected";

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
noaddr = ngx_string("0.0.0.0:1");


ngx_int_t
is_reserved_addr(ngx_str_t *addr)
{
    return addr->len == noaddr.len &&
           ngx_memcmp(addr->data, noaddr.data, noaddr.len - 2) == 0;
}

static ngx_int_t
ngx_dynamic_upstream_parse_url(ngx_url_t *u,
    ngx_pool_t *pool,
    ngx_dynamic_upstream_op_t *op)
{
    ngx_memzero(u, sizeof(ngx_url_t));

    u->url = op->server;
    u->default_port = 80;
    u->no_resolve = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE_SYNC
        ? 0 : 1;

    if (ngx_parse_url(pool, u) != NGX_OK) {
        if (u->err)
            op->err = u->err;
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    if (u->naddrs == 0) {
        if (u->no_resolve) {
            u->url = noaddr;
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


static ngx_flag_t
str_eq(ngx_str_t s1, ngx_str_t s2)
{
    return ngx_memn2cmp(s1.data, s2.data, s1.len, s2.len) == 0;
}


template <class PeerT> static ngx_flag_t
equals(PeerT *peer, ngx_str_t server, ngx_str_t name)
{
    if (server.data && name.data)
        return str_eq(server, peer->server) && str_eq(name, peer->name);

    assert(server.data != NULL);

    return str_eq(server, peer->server) || str_eq(server, peer->name);
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
            if (equals<PeerT>(peer, op->server, u->addrs[i].name)
                || (is_reserved_addr(&u->addrs[i].name)
                    && str_eq(peer->server, op->server))) {
                if ((op->backup && j == 0) || (!op->backup && j == 1)) {
                    op->status = NGX_HTTP_PRECONDITION_FAILED;
                    op->err = "can't change server type (primary<->backup)";
                    return NGX_ERROR;
                }
                op->status = NGX_HTTP_NOT_MODIFIED;
                op->err = "exists";
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
        npeer->max_fails = primary->peer->max_fails;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT)
        npeer->fail_timeout = op->fail_timeout;
    else
        npeer->fail_timeout = primary->peer->fail_timeout;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS)
        npeer->max_conns = op->max_conns;
    else
        npeer->max_conns = primary->peer->max_conns;

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

    if (!is_reserved_addr(&u->addrs[i].name)) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%V: added server %V peer %V",
                      &op->upstream, &u->url, &u->addrs[i].name);
    } else {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "%V: added server %V peer -.-.-.-",
                      &op->upstream, &u->url);
    }

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
    unsigned  i;
    unsigned  count = 0;

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary, op->no_lock);

    for (i = 0; i < u->naddrs; ++i) {
        if (ngx_dynamic_upstream_op_add_peer<PeersT, PeerT>(log, op, shpool,
                primary, u, i) == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (op->status == NGX_HTTP_OK)
           count++;
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

    if (op->status == NGX_HTTP_NOT_MODIFIED)
        return NGX_OK;

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
    ngx_url_t u;
};
typedef struct ngx_server_s ngx_server_t;


static ngx_uint_t
ngx_dynamic_upstream_op_server_exist(ngx_array_t *servers,
    ngx_str_t name)
{
    ngx_server_t  *server = (ngx_server_t *) servers->elts;
    unsigned       j;

    for (j = 0; j < servers->nelts; ++j)
        if (str_eq(server[j].name, name))
            return 1;

    return 0;
}


static ngx_uint_t
ngx_dynamic_upstream_op_peer_exist(ngx_array_t *servers,
    ngx_str_t name)
{
    ngx_server_t  *server = (ngx_server_t *) servers->elts;
    unsigned       i, j;

    for (j = 0; j < servers->nelts; ++j) {
        for (i = 0; i < server[j].u.naddrs; ++i) {
            if (str_eq(server[j].u.addrs[i].name, name))
                return 1;
        }
    }

    return 0;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_servers(PeersT *primary,
    ngx_array_t *servers, ngx_pool_t *pool, ngx_uint_t *hash)
{
    PeerT         *peer;
    PeersT        *peers;
    ngx_server_t  *server;
    ngx_uint_t     j = 0;

    *hash = 0;

    ngx_upstream_rr_peers_rlock<PeersT> lock(primary);

    for (peers = primary; peers && j < 2; peers = peers->next, j++) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if (!ngx_dynamic_upstream_op_server_exist(servers, peer->server)) {
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
                server->backup       = j == 1;
                server->weight       = peer->weight;
                server->max_fails    = peer->max_fails;
                server->fail_timeout = peer->fail_timeout;
#if defined(nginx_version) && (nginx_version >= 1011005)
                server->max_conns    = peer->max_conns;
#endif
            }

            *hash += ngx_crc32_short(peer->server.data,
                                     peer->server.len);
        }
    }

    return NGX_OK;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_check_hash(PeersT *primary, ngx_uint_t old_hash)
{
    PeerT        *peer;
    PeersT       *peers;
    ngx_uint_t    hash = 0;
    ngx_uint_t    i = 0;

    for (peers = primary; peers && i < 2; peers = peers->next, i++)
        for (peer = peers->peer; peer; peer = peer->next)
            hash += ngx_crc32_short(peer->server.data,
                                    peer->server.len);

    return hash == old_hash ? NGX_OK : NGX_AGAIN;
}


template <class PeersT, class PeerT> static ngx_int_t
ngx_dynamic_upstream_op_sync(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    PeersT *primary)
{
    unsigned       i, j;
    ngx_server_t  *server;
    PeerT         *peer;
    PeersT        *peers;
    unsigned       count = 0;
    ngx_array_t   *servers;
    ngx_uint_t     hash;

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

again:

    if (ngx_dynamic_upstream_op_servers<PeersT, PeerT>(primary,
                                                       servers,
                                                       guard.pool,
                                                       &hash)
            == NGX_ERROR)
    {
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        op->err = "no memory";
        return NGX_ERROR;
    }

    if (op->hash == hash) {
        op->status = NGX_HTTP_NOT_MODIFIED;
        return NGX_OK;
    }

    server = (ngx_server_t *) servers->elts;

    for (j = 0; j < servers->nelts; ++j) {
        op->server = server[j].name;
        if (ngx_dynamic_upstream_parse_url(&server[j].u, guard.pool,
                                           op) != NGX_OK)
            return NGX_ERROR;
    }

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary);

    if (ngx_dynamic_upstream_op_check_hash<PeersT, PeerT>(primary, hash)
            == NGX_AGAIN) {
        servers->nelts = 0;
        goto again;
    }

    op->no_lock = 1;

    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT;
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS;
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT;
#if defined(nginx_version) && (nginx_version >= 1011005)
    op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS;
#endif

    for (j = 0; j < servers->nelts; ++j) {

        op->server       = server[j].name;
        op->weight       = server[j].weight;
        op->backup       = server[j].backup;
        op->max_fails    = server[j].max_fails;
#if defined(nginx_version) && (nginx_version >= 1011005)
        op->max_conns    = server[j].max_conns;
#endif
        op->fail_timeout = server[j].fail_timeout;

        for (i = 0; i < server[j].u.naddrs; ++i) {

            if (str_eq(op->server, server[j].u.addrs[i].name))
                break;

            if (ngx_dynamic_upstream_op_add_peer<PeersT, PeerT>
                    (log, op, shpool, primary, &server[j].u, i) == NGX_ERROR)
                return NGX_ERROR;

            if (op->status == NGX_HTTP_OK)
                count++;
        }
    }

    i = 0;

    for (peers = primary; peers && i < 2; peers = peers->next, i++) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((peer->name.data[0] == '[' &&
                !(op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6)) ||
                !ngx_dynamic_upstream_op_peer_exist(servers, peer->name))
            {
                op->server = peer->name;
                if (ngx_dynamic_upstream_op_del<PeersT, PeerT>
                       (log, op, shpool, primary) == NGX_ERROR)
                    return NGX_ERROR;

                count++;
            }
        }
    }

    op->hash = hash;
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
            if (equals<PeerT>(peer, op->server, op->name)) {
                if (peers == primary && peers->number == 1) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    op->err = "single peer";
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

    ngx_upstream_rr_peers_wlock<PeersT> lock(primary, op->no_lock);

    for (peers = primary; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if (equals<PeerT>(peer, op->server, op->name)) {
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
