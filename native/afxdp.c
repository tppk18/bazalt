#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <xdp/xsk.h>

#define PM_FRAME_SIZE 2048u
#define PM_NUM_FRAMES 8192u
#define PM_RX_SIZE 4096u
#define PM_FILL_SIZE 8192u

#ifndef XDP_USE_SG
#define XDP_USE_SG 0u
#endif

struct pm_xdp_frame {
    const uint8_t *data;
    uint32_t len;
    uint64_t addr;
    uint32_t options;
};

struct pm_xdp_handle {
    struct xsk_umem *umem;
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    void *buffer;
    uint64_t buffer_size;
    uint32_t peek_idx;
    uint32_t peek_count;
    int multibuf_enabled;
};

static __thread char pm_error[256];

static void set_error(const char *what, int err) {
    if (err < 0) err = -err;
    snprintf(pm_error, sizeof(pm_error), "%s: %s (%d)", what, strerror(err), err);
}

const char *pm_xdp_last_error(void) {
    return pm_error;
}

static int seed_fill_ring(struct pm_xdp_handle *h) {
    uint32_t idx;
    uint32_t want = PM_NUM_FRAMES;
    uint32_t got = xsk_ring_prod__reserve(&h->fill, want, &idx);
    if (got != want) {
        set_error("fill ring reserve", ENOSPC);
        return -ENOSPC;
    }
    for (uint32_t i = 0; i < want; i++) {
        *xsk_ring_prod__fill_addr(&h->fill, idx + i) = ((uint64_t)i) * PM_FRAME_SIZE;
    }
    xsk_ring_prod__submit(&h->fill, want);
    return 0;
}

static int create_xsk_socket(
    struct pm_xdp_handle *h,
    const char *ifname,
    unsigned int queue_id,
    int prefer_zerocopy,
    uint32_t extra_bind_flags
) {
    struct xsk_socket_config scfg = {
        .rx_size = PM_RX_SIZE,
        .tx_size = 0,
        .libbpf_flags = 0,
        .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
        .bind_flags = XDP_USE_NEED_WAKEUP | extra_bind_flags | (prefer_zerocopy ? XDP_ZEROCOPY : 0),
    };

    int rc = xsk_socket__create(&h->xsk, ifname, queue_id, h->umem, &h->rx, NULL, &scfg);
    if (rc && prefer_zerocopy) {
        scfg.bind_flags = XDP_USE_NEED_WAKEUP | extra_bind_flags | XDP_COPY;
        rc = xsk_socket__create(&h->xsk, ifname, queue_id, h->umem, &h->rx, NULL, &scfg);
    }
    if (rc) {
        scfg.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
        scfg.bind_flags = XDP_USE_NEED_WAKEUP | extra_bind_flags | XDP_COPY;
        rc = xsk_socket__create(&h->xsk, ifname, queue_id, h->umem, &h->rx, NULL, &scfg);
    }
    return rc;
}

struct pm_xdp_handle *pm_xdp_open(const char *ifname, unsigned int queue_id, int prefer_zerocopy) {
    struct pm_xdp_handle *h = calloc(1, sizeof(*h));
    if (!h) {
        set_error("calloc", errno);
        return NULL;
    }

    h->buffer_size = ((uint64_t)PM_FRAME_SIZE) * PM_NUM_FRAMES;
    if (posix_memalign(&h->buffer, (size_t)getpagesize(), (size_t)h->buffer_size) != 0) {
        set_error("posix_memalign", errno ? errno : ENOMEM);
        free(h);
        return NULL;
    }
    memset(h->buffer, 0, (size_t)h->buffer_size);

    struct xsk_umem_config ucfg = {
        .fill_size = PM_FILL_SIZE,
        .comp_size = PM_FILL_SIZE,
        .frame_size = PM_FRAME_SIZE,
        .frame_headroom = 0,
        .flags = 0,
    };
    int rc = xsk_umem__create(&h->umem, h->buffer, h->buffer_size, &h->fill, &h->comp, &ucfg);
    if (rc) {
        set_error("xsk_umem__create", rc);
        free(h->buffer);
        free(h);
        return NULL;
    }

    // First try native/driver mode. If zero-copy is unsupported, retry native
    // mode with XDP_COPY. Many virtual NICs (including Docker/veth setups) do
    // not support native XDP at all, so the final AF_XDP attempt explicitly
    // switches to generic/SKB mode with copy semantics. Prefer scatter/gather
    // so packets larger than one UMEM frame are not dropped before userspace;
    // old kernels/drivers can fall back to the single-buffer mode.
    uint32_t sg_flag = (uint32_t)XDP_USE_SG;
    rc = create_xsk_socket(h, ifname, queue_id, prefer_zerocopy, sg_flag);
    if (!rc && sg_flag != 0) {
        h->multibuf_enabled = 1;
    } else if (rc && sg_flag != 0) {
        h->xsk = NULL;
        rc = create_xsk_socket(h, ifname, queue_id, prefer_zerocopy, 0);
    }
    if (rc) {
        set_error("xsk_socket__create", rc);
        xsk_umem__delete(h->umem);
        free(h->buffer);
        free(h);
        return NULL;
    }

    rc = seed_fill_ring(h);
    if (rc) {
        xsk_socket__delete(h->xsk);
        xsk_umem__delete(h->umem);
        free(h->buffer);
        free(h);
        return NULL;
    }
    return h;
}

int pm_xdp_fd(struct pm_xdp_handle *h) {
    if (!h || !h->xsk) return -1;
    return xsk_socket__fd(h->xsk);
}

int pm_xdp_multibuf_enabled(struct pm_xdp_handle *h) {
    if (!h) return 0;
    return h->multibuf_enabled;
}

int pm_xdp_peek(struct pm_xdp_handle *h, struct pm_xdp_frame *frames, unsigned int max_frames) {
    if (!h || !frames || max_frames == 0) return -EINVAL;
    if (h->peek_count != 0) return -EBUSY;

    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&h->rx, max_frames, &idx);
    if (!n) return 0;
    h->peek_idx = idx;
    h->peek_count = n;

    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&h->rx, idx + i);
        uint64_t addr = xsk_umem__add_offset_to_addr(desc->addr);
        frames[i].data = xsk_umem__get_data(h->buffer, addr);
        frames[i].len = desc->len;
        frames[i].addr = xsk_umem__extract_addr(desc->addr);
        frames[i].options = desc->options;
    }
    return (int)n;
}

int pm_xdp_stats(struct pm_xdp_handle *h, uint64_t *rx_dropped, uint64_t *rx_invalid_descs) {
    if (!h || !h->xsk || !rx_dropped || !rx_invalid_descs) return -EINVAL;

    struct xdp_statistics stats = {0};
    socklen_t len = sizeof(stats);
    int fd = xsk_socket__fd(h->xsk);
    if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, &stats, &len) < 0) {
        set_error("getsockopt XDP_STATISTICS", errno);
        return -errno;
    }
    *rx_dropped = stats.rx_dropped;
    *rx_invalid_descs = stats.rx_invalid_descs;
    return 0;
}

int pm_xdp_release(struct pm_xdp_handle *h, const struct pm_xdp_frame *frames, unsigned int count) {
    if (!h || !frames) return -EINVAL;
    if (count != h->peek_count) return -EINVAL;
    if (!count) return 0;

    uint32_t idx = 0;
    uint32_t reserved = xsk_ring_prod__reserve(&h->fill, count, &idx);
    if (reserved != count) {
        set_error("refill reserve", ENOSPC);
        return -ENOSPC;
    }
    for (uint32_t i = 0; i < count; i++) {
        *xsk_ring_prod__fill_addr(&h->fill, idx + i) = frames[i].addr;
    }
    xsk_ring_prod__submit(&h->fill, count);
    xsk_ring_cons__release(&h->rx, count);
    h->peek_count = 0;

    // XDP_USE_NEED_WAKEUP allows the driver to stop RX when it runs out of
    // FILL buffers. Refilling the ring alone is not sufficient in that state:
    // userspace must issue a syscall to wake the RX path. Do it immediately
    // after refill instead of waiting until our RX ring becomes completely
    // empty; otherwise packets can be dropped while we drain descriptors that
    // were already queued before the starvation event.
    if (xsk_ring_prod__needs_wakeup(&h->fill)) {
        struct pollfd pfd = {
            .fd = xsk_socket__fd(h->xsk),
            .events = POLLIN,
            .revents = 0,
        };
        int rc = poll(&pfd, 1, 0);
        if (rc < 0) {
            set_error("AF_XDP RX wakeup poll", errno);
            return -errno;
        }
    }
    return 0;
}

void pm_xdp_close(struct pm_xdp_handle *h) {
    if (!h) return;
    if (h->xsk) xsk_socket__delete(h->xsk);
    if (h->umem) xsk_umem__delete(h->umem);
    free(h->buffer);
    free(h);
}
