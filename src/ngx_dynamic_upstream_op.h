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


typedef union {
    ngx_http_upstream_rr_peer_t *http;
    ngx_stream_upstream_rr_peer_t *stream;
} ngx_upstream_rr_peer_t;

typedef union {
    ngx_http_upstream_rr_peers_t *http;
    ngx_stream_upstream_rr_peers_t *stream;
} ngx_upstream_rr_peers_t;


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
        no_lock = 1;
    }
};


template <class PeersT> struct ngx_upstream_rr_peers_rlock :
  protected ngx_upstream_rr_peers_lock<PeersT> {
    ngx_upstream_rr_peers_rlock(PeersT *p, int no_lock = 0) :
        ngx_upstream_rr_peers_lock<PeersT>(p, no_lock)
    {
        this->rlock();
    }
};


template <class PeersT> struct ngx_upstream_rr_peers_wlock :
  protected ngx_upstream_rr_peers_lock<PeersT> {
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
        peer = NULL;
    }
};


#ifdef __cplusplus
extern "C" {
#endif

ngx_int_t ngx_dynamic_upstream_build_op(ngx_http_request_t *r,
    ngx_dynamic_upstream_op_t *op);
ngx_int_t ngx_dynamic_upstream_op_impl(ngx_log_t *log,
    ngx_dynamic_upstream_op_t *op, ngx_slab_pool_t *shpool,
	ngx_upstream_rr_peers_t *primary);

#ifdef __cplusplus
}
#endif

#endif /* NGX_DYNAMIC_UPSTEAM_OP_H */
