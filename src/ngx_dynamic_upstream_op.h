/*
 * Copyright (c) 2015 Tatsuhiko Kubo (cubicdaiya@gmail.com>)
 * Copyright (C) 2018 Aleksei Konovkin (alkon2000@mail.ru)
 */

#ifndef NGX_DYNAMIC_UPSTREAM_OP_H
#define NGX_DYNAMIC_UPSTREAM_OP_H

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


template <class PeersT>
class ngx_upstream_rr_peers_lock {
    PeersT *peers;
    int     no_lock;

protected:

    ngx_upstream_rr_peers_lock(PeersT *p, int no)
      : peers(p), no_lock(no)
    {}

    virtual ~ngx_upstream_rr_peers_lock()
    {
        if (!no_lock)
            ngx_rwlock_unlock(&peers->rwlock);
    }

    ngx_inline void
    rlock()
    {
        if (!no_lock)
            ngx_rwlock_rlock(&peers->rwlock);
    }

    ngx_inline void
    wlock()
    {
        if (!no_lock)
            ngx_rwlock_wlock(&peers->rwlock);
    }

public:

    ngx_inline void
    release()
    {
        if (!no_lock) {
            ngx_rwlock_unlock(&peers->rwlock);
            no_lock = 1;
        }
    }
};


template <class PeersT> struct ngx_upstream_rr_peers_rlock :
  public ngx_upstream_rr_peers_lock<PeersT> {
    ngx_upstream_rr_peers_rlock(PeersT *p, int no_lock = 0) :
        ngx_upstream_rr_peers_lock<PeersT>(p, no_lock)
    {
        this->rlock();
    }
};


template <class PeersT> struct ngx_upstream_rr_peers_wlock :
  public ngx_upstream_rr_peers_lock<PeersT> {
    ngx_upstream_rr_peers_wlock(PeersT *p, int no_lock = 0) :
        ngx_upstream_rr_peers_lock<PeersT>(p, no_lock)
    {
        this->wlock();
    }
};


template <class PeerT>
class ngx_upstream_rr_peer_lock {
    PeerT *peer;

public:

    ngx_upstream_rr_peer_lock(PeerT *p)
      : peer(p)
    {
        ngx_rwlock_wlock(&peer->lock);
    }

    virtual ~ngx_upstream_rr_peer_lock()
    {
        if (peer != NULL)
            ngx_rwlock_unlock(&peer->lock);
    }

    ngx_inline void
    release()
    {
        ngx_rwlock_unlock(&peer->lock);
        peer = NULL;
    }
};


template <class S>
struct TypeSelect {};


template <>
struct TypeSelect<ngx_http_upstream_srv_conf_t> {
    typedef ngx_http_upstream_main_conf_t  main_type;
    typedef ngx_http_upstream_srv_conf_t   srv_type;
    typedef ngx_http_upstream_rr_peers_t   peers_type;
    typedef ngx_http_upstream_rr_peer_t    peer_type;

    static main_type * main_conf()
    {
        return (main_type *) ngx_http_cycle_get_module_main_conf(ngx_cycle,
            ngx_http_upstream_module);
    }

    static void make_op(ngx_dynamic_upstream_op_t *op)
    {
        op->op_param &= ~NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM;
    }
};


template <>
struct TypeSelect<ngx_stream_upstream_srv_conf_t> {
    typedef ngx_stream_upstream_main_conf_t  main_type;
    typedef ngx_stream_upstream_srv_conf_t   srv_type;
    typedef ngx_stream_upstream_rr_peers_t   peers_type;
    typedef ngx_stream_upstream_rr_peer_t    peer_type;

    static main_type * main_conf()
    {
        return (main_type *) ngx_stream_cycle_get_module_main_conf(ngx_cycle,
            ngx_stream_upstream_module);
    }

    static void make_op(ngx_dynamic_upstream_op_t *op)
    {
        op->op_param |= NGX_DYNAMIC_UPSTEAM_OP_PARAM_STREAM;
    }
};


#ifdef __cplusplus
extern "C" {
#endif

ngx_int_t ngx_dynamic_upstream_build_op(ngx_http_request_t *r,
    ngx_dynamic_upstream_op_t *op);
ngx_int_t ngx_dynamic_upstream_op_impl(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
    void *peers);

#ifdef __cplusplus
}
#endif

#endif /* NGX_DYNAMIC_UPSTEAM_OP_H */
