#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <assert.h>


#include "ngx_dynamic_upstream_module.h"
#include "ngx_dynamic_upstream_op.h"
#include "ngx_inet_slab.h"


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
    ngx_string("arg_resolve"),
	ngx_string("arg_ipv6")
};


static ngx_int_t
ngx_dynamic_upstream_is_shpool_range(ngx_slab_pool_t *shpool, void *p);


static ngx_int_t
ngx_dynamic_upstream_http_op_add(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, ngx_http_upstream_rr_peers_t *primary);


static ngx_int_t
ngx_dynamic_upstream_stream_op_add(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_stream_upstream_rr_peers_t *primary);


static ngx_int_t
ngx_dynamic_upstream_http_op_del(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_http_upstream_rr_peers_t *primary);


static ngx_int_t
ngx_dynamic_upstream_stream_op_del(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_stream_upstream_rr_peers_t *primary);


static ngx_int_t
ngx_dynamic_upstream_http_op_update(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_http_upstream_rr_peers_t *primary);


static ngx_int_t
ngx_dynamic_upstream_stream_op_update(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_stream_upstream_rr_peers_t *primary);


static ngx_int_t
ngx_dynamic_upstream_is_shpool_range(ngx_slab_pool_t *shpool, void *p)
{
    if ((u_char *) p < shpool->start || (u_char *) p > shpool->end) {
        return 0;
    }

    return 1;
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

    /* default setting for op */
    op->op = NGX_DYNAMIC_UPSTEAM_OP_LIST;
    op->status = NGX_HTTP_OK;
    ngx_str_null(&op->upstream);
    op->weight       = 1;
    op->max_fails    = 1;
    op->fail_timeout = 10;

    args = (ngx_str_t *)&ngx_dynamic_upstream_params;
    args_size = sizeof(ngx_dynamic_upstream_params) / sizeof(ngx_str_t);
    for (i=0;i<args_size;i++) {
        low = ngx_pnalloc(r->pool, args[i].len);
        if (low == NULL) {
            op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no memory");
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
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "weight is not number");
                    return NGX_ERROR;
                }
                op->op |= NGX_DYNAMIC_UPSTEAM_OP_PARAM;
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT;
                op->verbose = 1;

            } else if (ngx_strcmp("arg_max_fails", args[i].data) == 0) {
                op->max_fails = ngx_atoi(var->data, var->len);
                if (op->max_fails == NGX_ERROR) {
                    op->status = NGX_HTTP_BAD_REQUEST;
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "max_fails is not number");
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
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "max_conns is not number");
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
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "fail_timeout is not number");
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

            } else if (ngx_strcmp("arg_resolve", args[i].data) == 0) {
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;

            } else if (ngx_strcmp("arg_ipv6", args[i].data) == 0) {
                op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6;

            }
        }
    }

    /* can not add and remove at once */
    if ((op->op & NGX_DYNAMIC_UPSTEAM_OP_ADD) &&
        (op->op & NGX_DYNAMIC_UPSTEAM_OP_REMOVE))
    {
        op->status = NGX_HTTP_BAD_REQUEST;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "add and remove at once are not allowed");
        return NGX_ERROR;
    }

    if (op->op & NGX_DYNAMIC_UPSTEAM_OP_ADD) {
        op->op = NGX_DYNAMIC_UPSTEAM_OP_ADD;
    } else if (op->op & NGX_DYNAMIC_UPSTEAM_OP_REMOVE) {
        op->op = NGX_DYNAMIC_UPSTEAM_OP_REMOVE;
    }

    /* can not up and down at once */
    if (op->up && op->down) {
        op->status = NGX_HTTP_BAD_REQUEST;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "down and up at once are not allowed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_dynamic_upstream_op_impl(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, ngx_upstream_rr_peers_t *peers)
{
    ngx_int_t rc = NGX_OK;

    if (shpool) {
        ngx_shmtx_lock(&shpool->mutex);
    }

    switch (op->op) {
    case NGX_DYNAMIC_UPSTEAM_OP_ADD:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
           ? ngx_dynamic_upstream_stream_op_add(log, op, shpool, peers->stream)
           : ngx_dynamic_upstream_http_op_add(log, op, shpool, peers->http);
        break;
    case NGX_DYNAMIC_UPSTEAM_OP_REMOVE:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
           ? ngx_dynamic_upstream_stream_op_del(log, op, shpool, peers->stream)
           : ngx_dynamic_upstream_http_op_del(log, op, shpool, peers->http);
        break;
    case NGX_DYNAMIC_UPSTEAM_OP_PARAM:
        rc = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM
           ? ngx_dynamic_upstream_stream_op_update(log, op, peers->stream)
           : ngx_dynamic_upstream_http_op_update(log, op, peers->http);
        break;
    case NGX_DYNAMIC_UPSTEAM_OP_LIST:
    default:
        rc = NGX_OK;
        break;
    }

    if (shpool) {
        ngx_shmtx_unlock(&shpool->mutex);
    }

    return rc;
}


static ngx_int_t
ngx_dynamic_upstream_parse_url(ngx_url_t *u,
	ngx_log_t *log,
	ngx_slab_pool_t *shpool,
	ngx_dynamic_upstream_op_t *op)
{
    ngx_memzero(u, sizeof(ngx_url_t));

    u->url = op->server;
    u->default_port = 80;

    if (ngx_parse_url_slab(shpool, u) != NGX_OK) {
        if (u->err) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "%s in upstream \"%V\"", u->err, &u->url);
        }
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_upstream_http_op_add_peer(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_http_upstream_rr_peers_t *primary,
	ngx_url_t *u, int i)
{
    ngx_http_upstream_rr_peer_t   *peer, *last = NULL, *new_peer;
    ngx_http_upstream_rr_peers_t  *peers, *backup = primary->next;

    if (u->addrs[i].name.data[0] == '[' &&
    		!(op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6)) {
    	    return NGX_OK;
    }

    for (peers = primary; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if (u->addrs[i].name.len == peer->name.len &&
                ngx_strncmp(u->addrs[i].name.data, peer->name.data,
                            peer->name.len) == 0) {
                op->status = NGX_HTTP_BAD_REQUEST;
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "server %V already exists in upstream",
							  &u->addrs[i].name);
                return NGX_ERROR;
            }
            if ( (op->backup == 0 && peers == primary) ||
                 (op->backup == 1 && peers == backup) ) {
                last = peer;
            }
        }
    }

    if (op->backup) {
        if (backup == NULL) {
            assert(last == NULL);
            backup = ngx_slab_calloc_locked(shpool,
                sizeof(ngx_http_upstream_rr_peers_t));
            if (backup == NULL) {
                op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                ngx_log_error(NGX_LOG_ERR, log, 0, "no shared memory");
                return NGX_ERROR;
            }
            backup->shpool = primary->shpool;
            backup->name = primary->name;
        }

        peers = backup;
    } else {
        peers = primary;
    }

    new_peer = ngx_slab_calloc_locked(shpool,
                                      sizeof(ngx_http_upstream_rr_peer_t));
    if (new_peer != NULL) {
    	    new_peer->server.data = ngx_slab_calloc_locked(shpool, u->url.len + 1);
    	    if (new_peer->server.data == NULL) {
    	        	ngx_slab_free_locked(shpool, new_peer);
    	        	new_peer = NULL;
    	    }
    }

    if (new_peer == NULL) {
        if (backup && primary->next == NULL) {
            ngx_slab_free_locked(shpool, backup);
        }
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_log_error(NGX_LOG_ERR, log, 0, "no shared memory");
        return NGX_ERROR;
    }

    new_peer->name       = u->addrs[i].name;
    new_peer->server.len = u->url.len;
    ngx_memcpy(new_peer->server.data, u->url.data, u->url.len);
    new_peer->sockaddr   = u->addrs[i].sockaddr;
    new_peer->socklen    = u->addrs[i].socklen;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT) {
        new_peer->weight = op->weight;
        new_peer->effective_weight = op->weight;
        new_peer->current_weight = 0;
    } else {
        new_peer->weight = 1;
        new_peer->effective_weight = 1;
        new_peer->current_weight = 0;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS) {
        new_peer->max_fails = op->max_fails;
    } else {
        new_peer->max_fails = 1;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT) {
        new_peer->fail_timeout = op->fail_timeout;
    } else {
        new_peer->fail_timeout = 10;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN) {
        new_peer->down = op->down;
    }

    if (last == NULL) {
        peers->peer = new_peer;
    } else {
        last->next = new_peer;
    }

    peers->total_weight += new_peer->weight;
    peers->single = (peers->number == 0);
    peers->weighted = (peers->total_weight != peers->number);
    peers->number++;

    if (backup && primary->next == NULL) {
        primary->next = backup;
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "added server %V peer %V", &u->url, &u->addrs[i].name);

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_upstream_http_op_add(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_http_upstream_rr_peers_t *primary)
{
    ngx_url_t u;
    unsigned  i;
    int       resolve = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;

    if (shpool == NULL) {
        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "add is possible only for upstream with 'zone'");
        return NGX_ERROR;
    }

    if (ngx_dynamic_upstream_parse_url(&u, log, shpool, op) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_upstream_rr_peers_wlock(primary);

    for (i = 0; i < u.naddrs; ++i) {
        if (ngx_dynamic_upstream_http_op_add_peer(log, op, shpool, primary, &u, i) == NGX_ERROR) {
        	    if (op->status == NGX_HTTP_INTERNAL_SERVER_ERROR || !resolve) {
                ngx_http_upstream_rr_peers_unlock(primary);
                ngx_slab_free_locked(shpool, u.addrs);
                return NGX_ERROR;
        	    }
        }
        if (!resolve) {
        	    break;
        }
    }

    ngx_http_upstream_rr_peers_unlock(primary);

    ngx_slab_free_locked(shpool, u.addrs);

    op->status = NGX_HTTP_OK;

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_upstream_stream_op_add_peer(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_stream_upstream_rr_peers_t *primary,
	ngx_url_t *u, unsigned i)
{
    ngx_stream_upstream_rr_peer_t   *peer, *last = NULL, *new_peer;
    ngx_stream_upstream_rr_peers_t  *peers, *backup = primary->next;

    if (u->addrs[i].name.data[0] == '[' &&
    		!(op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_IPV6)) {
    	    return NGX_OK;
    }

    for (peers = primary; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if (u->addrs[i].name.len == peer->name.len &&
                ngx_strncmp(u->addrs[i].name.data, peer->name.data,
                            peer->name.len) == 0) {
                op->status = NGX_HTTP_BAD_REQUEST;
                ngx_log_error(NGX_LOG_ERR, log, 0,
                              "server %V already exists in upstream",
							 &u->addrs[i].name);
                return NGX_ERROR;
            }
            if ( (op->backup == 0 && peers == primary) ||
                 (op->backup == 1 && peers == backup) ) {
                last = peer;
            }
        }
    }

    if (op->backup) {
        if (backup == NULL) {
            assert(last == NULL);
            backup = ngx_slab_calloc_locked(shpool,
                sizeof(ngx_stream_upstream_rr_peers_t));
            if (backup == NULL) {
                op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                ngx_log_error(NGX_LOG_ERR, log, 0, "no shared memory");
                return NGX_ERROR;
            }
            backup->shpool = primary->shpool;
            backup->name = primary->name;
        }

        peers = backup;
    } else {
        peers = primary;
    }

    new_peer = ngx_slab_calloc_locked(shpool,
                                      sizeof(ngx_stream_upstream_rr_peer_t));
    if (new_peer != NULL) {
    	    new_peer->server.data = ngx_slab_calloc_locked(shpool, u->url.len + 1);
    	    if (new_peer->server.data == NULL) {
    	        	ngx_slab_free_locked(shpool, new_peer);
    	        	new_peer = NULL;
    	    }
    }

    if (new_peer == NULL) {
        if (backup && primary->next == NULL) {
            ngx_slab_free_locked(shpool, backup);
        }
        op->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_log_error(NGX_LOG_ERR, log, 0, "no shared memory");
        return NGX_ERROR;
    }

    new_peer->name       = u->addrs[i].name;
    new_peer->server.len = u->url.len;
    ngx_memcpy(new_peer->server.data, u->url.data, u->url.len);
    new_peer->sockaddr   = u->addrs[i].sockaddr;
    new_peer->socklen    = u->addrs[i].socklen;

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT) {
        new_peer->weight = op->weight;
        new_peer->effective_weight = op->weight;
        new_peer->current_weight = 0;
    } else {
        new_peer->weight = 1;
        new_peer->effective_weight = 1;
        new_peer->current_weight = 0;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS) {
        new_peer->max_fails = op->max_fails;
    } else {
        new_peer->max_fails = 1;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT) {
        new_peer->fail_timeout = op->fail_timeout;
    } else {
        new_peer->fail_timeout = 10;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN) {
        new_peer->down = op->down;
    }

    if (last == NULL) {
        peers->peer = new_peer;
    } else {
        last->next = new_peer;
    }

    peers->total_weight += new_peer->weight;
    peers->single = (peers->number == 0);
    peers->weighted = (peers->total_weight != peers->number);
    peers->number++;

    if (backup && primary->next == NULL) {
        primary->next = backup;
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "added server %V peer %V", &u->url, &u->addrs[i].name);

    return NGX_OK;
}


static ngx_int_t
ngx_dynamic_upstream_stream_op_add(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    ngx_stream_upstream_rr_peers_t *primary)
{
    ngx_url_t u;
    unsigned  i;
    int       resolve = op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_RESOLVE;

    if (shpool == NULL) {
        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "add is possible only for upstream with 'zone'");
        return NGX_ERROR;
    }

    if (ngx_dynamic_upstream_parse_url(&u, log, shpool, op) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_stream_upstream_rr_peers_wlock(primary);

    for (i = 0; i < u.naddrs; ++i) {
        if (ngx_dynamic_upstream_stream_op_add_peer(log, op, shpool, primary, &u, i) == NGX_ERROR) {
        	    if (op->status == NGX_HTTP_INTERNAL_SERVER_ERROR || !resolve) {
                ngx_stream_upstream_rr_peers_unlock(primary);
                ngx_slab_free_locked(shpool, u.addrs);
                return NGX_ERROR;
        	    }
        }
        if (!resolve) {
        	    break;
        }
    }

    ngx_http_upstream_rr_peers_unlock(primary);

    ngx_slab_free_locked(shpool, u.addrs);

    op->status = NGX_HTTP_OK;

    return NGX_OK;
}


typedef ngx_int_t (*cleanup_t) (ngx_slab_pool_t *shpool, void *peer);


typedef struct {
    ngx_slab_pool_t *shpool;
    void            *peer;
    cleanup_t        free;
} ngx_dynamic_cleanup_t;


static ngx_connection_t dumb_conn = {
    .fd = -1
};


static void
ngx_dynamic_cleanup(ngx_event_t *ev);


static ngx_event_t cleanup_ev = {
    .handler = ngx_dynamic_cleanup,
    .data = &dumb_conn,
    .log = NULL
};


static ngx_array_t *trash = NULL;


static ngx_array_t *
ngx_dynamic_trash_init()
{
    trash = ngx_array_create(ngx_cycle->pool, 100,
                             sizeof(ngx_dynamic_cleanup_t));

    if (trash) {
        cleanup_ev.log = ngx_cycle->log;
        ngx_add_timer(&cleanup_ev, 1000);
    }

    return trash;
}


static void
ngx_dynamic_add_to_trash(ngx_slab_pool_t *shpool, void *peer, cleanup_t cb)
{
    ngx_dynamic_cleanup_t  *p;

    if (trash == NULL) {
        if (ngx_dynamic_trash_init() == NULL) {
            return;
        }
    }

    p = ngx_array_push(trash);

    if (p != NULL) {
        p->shpool = shpool;
        p->peer = peer;
        p->free = cb;
    }
}


static void
ngx_dynamic_cleanup(ngx_event_t *ev)
{
    ngx_dynamic_cleanup_t *elts = trash->elts;
    ngx_uint_t             i, j = 0;

    if (trash->nelts == 0) {
        goto settimer;
    }

    for (i = 0; i < trash->nelts; i++) {
        if (elts[i].free(elts[i].shpool, elts[i].peer) == -1) {
            elts[j++] = elts[i];
        }
    }

    trash->nelts = j;

settimer:

    if (!ngx_exiting) {
        ngx_add_timer(ev, 1000);
    }
}


static ngx_int_t
ngx_http_dynamic_upstream_free_peer(ngx_slab_pool_t *shpool, void *p)
{
    ngx_http_upstream_rr_peer_t *peer = p;

    ngx_rwlock_wlock(&peer->lock);

    if (peer->conns == 0) {
        if (ngx_dynamic_upstream_is_shpool_range(shpool, peer->server.data)) {
            ngx_slab_free_locked(shpool, peer->server.data);
        }

        if (ngx_dynamic_upstream_is_shpool_range(shpool, peer->name.data)) {
            ngx_slab_free_locked(shpool, peer->name.data);
        }

        if (ngx_dynamic_upstream_is_shpool_range(shpool, peer->sockaddr)) {
            ngx_slab_free_locked(shpool, peer->sockaddr);
        }

        ngx_slab_free_locked(shpool, peer);

        return 0;
    }

    ngx_rwlock_unlock(&peer->lock);

    return -1;
}


static void
ngx_http_dynamic_upstream_op_free_peer(ngx_slab_pool_t *shpool,
    ngx_http_upstream_rr_peer_t *peer)
{
    if (ngx_http_dynamic_upstream_free_peer(shpool, peer) == -1) {
        /* move to trash */
        ngx_dynamic_add_to_trash(shpool, peer,
                                 ngx_http_dynamic_upstream_free_peer);
    }
}


static ngx_int_t
ngx_dynamic_upstream_http_op_del(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, ngx_http_upstream_rr_peers_t *primary)
{
    ngx_http_upstream_rr_peer_t   *peer, *deleted, *prev;
    ngx_http_upstream_rr_peers_t  *peers, *backup = primary->next;
    ngx_uint_t                     count = 0;

    if (shpool == NULL) {
        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "remove is possible only for upstream with 'zone'");
        return NGX_ERROR;
    }

    ngx_stream_upstream_rr_peers_wlock(primary);

again:

    deleted = NULL;

    for (peers = primary; peers; peers = peers->next) {
        prev = NULL;
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((op->server.len == peer->server.len &&
                 ngx_strncmp(op->server.data, peer->server.data,
                             peer->server.len) == 0) ||
            	    (op->server.len == peer->name.len &&
                 ngx_strncmp(op->server.data, peer->name.data,
                             peer->name.len) == 0)) {
                if (peers == primary && peers->number == 1) {
                   op->status = NGX_HTTP_BAD_REQUEST;
                   return NGX_ERROR;
                }
                deleted = peer;
                peer = peer->next;
                count++;
                goto delete;
            }
            prev = peer;
        }
    }

delete:

    /* not found */
    if (deleted == NULL) {
        ngx_stream_upstream_rr_peers_unlock(primary);
    	    if (count == 0) {
			op->status = NGX_HTTP_BAD_REQUEST;
			ngx_log_error(NGX_LOG_ERR, log, 0, "server or peer %V is not found", &op->server);
			return NGX_ERROR;
    	    }
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
        ngx_slab_free_locked(shpool, backup);
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "removed server %V peer %V", &op->server, &deleted->name);

    ngx_http_dynamic_upstream_op_free_peer(shpool, deleted);

    goto again;
}


static ngx_int_t
ngx_stream_dynamic_upstream_free_peer(ngx_slab_pool_t *shpool, void *p)
{
    ngx_stream_upstream_rr_peer_t *peer = p;

    ngx_rwlock_wlock(&peer->lock);

    if (peer->conns == 0) {
        if (ngx_dynamic_upstream_is_shpool_range(shpool, peer->server.data)) {
            ngx_slab_free_locked(shpool, peer->server.data);
        }

        if (ngx_dynamic_upstream_is_shpool_range(shpool, peer->name.data)) {
            ngx_slab_free_locked(shpool, peer->name.data);
        }

        if (ngx_dynamic_upstream_is_shpool_range(shpool, peer->sockaddr)) {
            ngx_slab_free_locked(shpool, peer->sockaddr);
        }

        ngx_slab_free_locked(shpool, peer);

        return 0;
    }

    ngx_rwlock_unlock(&peer->lock);

    return -1;
}


static void
ngx_stream_dynamic_upstream_op_free_peer(ngx_slab_pool_t *shpool,
    ngx_stream_upstream_rr_peer_t *peer)
{
    if (ngx_stream_dynamic_upstream_free_peer(shpool, peer) == -1) {
        /* move to trash */
        ngx_dynamic_add_to_trash(shpool, peer,
                                 ngx_stream_dynamic_upstream_free_peer);
    }
}


static ngx_int_t
ngx_dynamic_upstream_stream_op_del(ngx_log_t *log, ngx_dynamic_upstream_op_t *op,
    ngx_slab_pool_t *shpool, ngx_stream_upstream_rr_peers_t *primary)
{
    ngx_stream_upstream_rr_peer_t   *peer, *deleted, *prev;
    ngx_stream_upstream_rr_peers_t  *peers, *backup = primary->next;
    ngx_uint_t                       count = 0;

    if (shpool == NULL) {
        op->status = NGX_HTTP_NOT_IMPLEMENTED;
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "remove is possible only for upstream with 'zone'");
        return NGX_ERROR;
    }

    ngx_stream_upstream_rr_peers_wlock(primary);

again:

    deleted = NULL;

    for (peers = primary; peers; peers = peers->next) {
        prev = NULL;
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((op->server.len == peer->server.len &&
                 ngx_strncmp(op->server.data, peer->server.data,
                             peer->server.len) == 0) ||
            	    (op->server.len == peer->name.len &&
                 ngx_strncmp(op->server.data, peer->name.data,
                             peer->name.len) == 0)) {
                if (peers == primary && peers->number == 1) {
                   op->status = NGX_HTTP_BAD_REQUEST;
                   return NGX_ERROR;
                }
                deleted = peer;
                peer = peer->next;
                count++;
                goto delete;
            }
            prev = peer;
        }
    }

delete:

    /* not found */
    if (deleted == NULL) {
        ngx_stream_upstream_rr_peers_unlock(primary);
    	    if (count == 0) {
			op->status = NGX_HTTP_BAD_REQUEST;
			ngx_log_error(NGX_LOG_ERR, log, 0, "server or peer %V is not found", &op->server);
			return NGX_ERROR;
    	    }
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
        ngx_slab_free_locked(shpool, backup);
    }

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "removed server %V peer %V", &op->server, &deleted->name);

    ngx_stream_dynamic_upstream_op_free_peer(shpool, deleted);

    goto again;
}


static void
ngx_dynamic_upstream_http_op_update_peer(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_http_upstream_rr_peers_t *peers,
	ngx_http_upstream_rr_peer_t *peer)
{
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT) {
        peers->total_weight -= peer->weight;
        peers->total_weight += op->weight;
        peers->weighted = peers->total_weight != peers->number;
        peer->weight = op->weight;
        peer->current_weight = op->weight;
        peer->effective_weight = op->weight;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS) {
        peer->max_fails = op->max_fails;
    }

#if defined(nginx_version) && (nginx_version >= 1011005)
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS) {
        peer->max_conns = op->max_conns;
    }
#endif

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT) {
        peer->fail_timeout = op->fail_timeout;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP) {
        peer->down = 0;
        peer->checked = ngx_time();
        peer->fails = 0;
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "up peer %V", &peer->name);
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN) {
        peer->down = 1;
        peer->checked = ngx_time();
        peer->fails = peer->max_fails;
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "down peer %V", &peer->name);
    }

}


static ngx_int_t
ngx_dynamic_upstream_http_op_update(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_http_upstream_rr_peers_t *primary)
{
    ngx_http_upstream_rr_peer_t   *peer;
    ngx_http_upstream_rr_peers_t  *peers;
    unsigned                       count = 0;

    ngx_http_upstream_rr_peers_wlock(primary);

    for (peers = primary; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((op->server.len == peer->server.len &&
                 ngx_strncmp(op->server.data, peer->server.data,
                             peer->server.len) == 0) ||
            	    (op->server.len == peer->name.len &&
                 ngx_strncmp(op->server.data, peer->name.data,
                             peer->server.len) == 0)) {
                ngx_http_upstream_rr_peer_lock(primary, peer);
                ngx_dynamic_upstream_http_op_update_peer(log, op, peers, peer);
                count++;
                ngx_http_upstream_rr_peer_unlock(primary, peer);
            }
        }
    }

    ngx_stream_upstream_rr_peers_unlock(primary);

    if (count == 0) {
        op->status = NGX_HTTP_BAD_REQUEST;
		ngx_log_error(NGX_LOG_ERR, log, 0, "server or peer %V is not found", &op->server);
		return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_dynamic_upstream_stream_op_update_peer(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_stream_upstream_rr_peers_t *peers,
	ngx_stream_upstream_rr_peer_t *peer)
{
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_WEIGHT) {
        peers->total_weight -= peer->weight;
        peers->total_weight += op->weight;
        peers->weighted = peers->total_weight != peers->number;
        peer->weight = op->weight;
        peer->current_weight = op->weight;
        peer->effective_weight = op->weight;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_FAILS) {
        peer->max_fails = op->max_fails;
    }

#if defined(nginx_version) && (nginx_version >= 1011005)
    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_MAX_CONNS) {
        peer->max_conns = op->max_conns;
    }
#endif

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_FAIL_TIMEOUT) {
        peer->fail_timeout = op->fail_timeout;
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_UP) {
        peer->down = 0;
        peer->checked = ngx_time();
        peer->fails = 0;
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "up peer %V", &peer->name);
    }

    if (op->op_param & NGX_DYNAMIC_UPSTEAM_OP_PARAM_DOWN) {
        peer->down = 1;
        peer->checked = ngx_time();
        peer->fails = peer->max_fails;
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "down peer %V", &peer->name);
    }
}


static ngx_int_t
ngx_dynamic_upstream_stream_op_update(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_stream_upstream_rr_peers_t *primary)
{
    ngx_stream_upstream_rr_peer_t   *peer;
    ngx_stream_upstream_rr_peers_t  *peers;
    unsigned                         count = 0;

    ngx_stream_upstream_rr_peers_wlock(primary);

    for (peers = primary; peers; peers = peers->next) {
        for (peer = peers->peer; peer; peer = peer->next) {
            if ((op->server.len == peer->server.len &&
                 ngx_strncmp(op->server.data, peer->server.data,
                             peer->server.len) == 0) ||
            	    (op->server.len == peer->name.len &&
                 ngx_strncmp(op->server.data, peer->name.data,
                             peer->server.len) == 0)) {
                ngx_stream_upstream_rr_peer_lock(primary, peer);
                ngx_dynamic_upstream_stream_op_update_peer(log, op, peers, peer);
                count++;
                ngx_stream_upstream_rr_peer_unlock(primary, peer);
            }
        }
    }

    ngx_stream_upstream_rr_peers_unlock(primary);

    if (count == 0) {
        op->status = NGX_HTTP_BAD_REQUEST;
		ngx_log_error(NGX_LOG_ERR, log, 0, "server or peer %V is not found", &op->server);
		return NGX_ERROR;
    }

    return NGX_OK;
}
