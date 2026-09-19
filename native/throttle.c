#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct pm_throttle_key {
    uint32_t prefixlen;
    uint32_t addr;
};

struct pm_throttle_value {
    uint32_t drop_percent;
    uint32_t reserved;
    uint64_t expires_at_ns;
    uint64_t seen_packets;
    uint64_t seen_bytes;
    uint64_t dropped_packets;
    uint64_t dropped_bytes;
};

struct pm_throttle_handle {
    struct bpf_object *object;
    struct bpf_link *link;
    int rules_fd;
    int program_fd;
    unsigned int ifindex;
    uint32_t attach_mode;
    uint32_t program_id;
    uint8_t program_tag[8];
    int netlink_attached;
    int owner_lock_fd;
};

enum {
    PM_THROTTLE_MODE_UNKNOWN = 0,
    PM_THROTTLE_MODE_NATIVE_LINK = 1,
    PM_THROTTLE_MODE_NATIVE_NETLINK = 2,
    PM_THROTTLE_MODE_GENERIC_NETLINK = 3,
};

static __thread char pm_throttle_error[256];

static void set_throttle_error(const char *what, int error) {
    if (error < 0) error = -error;
    snprintf(pm_throttle_error, sizeof(pm_throttle_error), "%s: %s (%d)", what, strerror(error), error);
}

const char *pm_throttle_last_error(void) {
    return pm_throttle_error;
}

static int query_xdp(struct pm_throttle_handle *handle, struct bpf_xdp_query_opts *opts);

static int monotonic_ns(uint64_t *value) {
    struct timespec now = {0};
    if (!value) return -EINVAL;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -errno;
    *value = ((uint64_t)now.tv_sec * 1000000000ULL) + (uint64_t)now.tv_nsec;
    return 0;
}

static void make_key(struct pm_throttle_key *key, const uint8_t addr[4], uint32_t prefix_len) {
    memset(key, 0, sizeof(*key));
    key->prefixlen = prefix_len;
    memcpy(&key->addr, addr, 4);
}

static int load_own_program_id(struct pm_throttle_handle *handle) {
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    __u32 len = sizeof(info);
    int rc = bpf_obj_get_info_by_fd(handle->program_fd, &info, &len);
    if (rc != 0) {
        int error = errno ? errno : EIO;
        set_throttle_error("read throttle BPF program id", error);
        return -error;
    }
    if (info.id == 0) {
        set_throttle_error("read throttle BPF program id", ENOENT);
        return -ENOENT;
    }
    handle->program_id = info.id;
    memcpy(handle->program_tag, info.tag, sizeof(handle->program_tag));
    return 0;
}

static int acquire_owner_lock(struct pm_throttle_handle *handle) {
    char path[128];
    snprintf(path, sizeof(path), "/run/bazalt-throttle-%u.lock", handle->ifindex);
    int fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) {
        int error = errno;
        set_throttle_error("open throttle ownership lock", error);
        return -error;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int error = errno;
        close(fd);
        set_throttle_error("acquire throttle ownership lock", error);
        return -error;
    }
    handle->owner_lock_fd = fd;
    return 0;
}

static int program_is_stale_own_copy(struct pm_throttle_handle *handle, uint32_t program_id) {
    if (program_id == 0 || program_id == handle->program_id)
        return 0;
    int fd = bpf_prog_get_fd_by_id(program_id);
    if (fd < 0)
        return 0;
    struct bpf_prog_info info;
    memset(&info, 0, sizeof(info));
    __u32 len = sizeof(info);
    int rc = bpf_obj_get_info_by_fd(fd, &info, &len);
    close(fd);
    if (rc != 0)
        return 0;
    if (info.type != BPF_PROG_TYPE_XDP)
        return 0;
    if (strncmp((const char *)info.name, "bazalt_throttle", sizeof(info.name)) != 0)
        return 0;
    return memcmp(info.tag, handle->program_tag, sizeof(handle->program_tag)) == 0;
}

static int detach_stale_own_netlink(struct pm_throttle_handle *handle) {
    struct bpf_xdp_query_opts opts;
    int rc = query_xdp(handle, &opts);
    if (rc != 0)
        return rc;

    if (program_is_stale_own_copy(handle, opts.drv_prog_id)) {
        rc = bpf_xdp_detach((int)handle->ifindex, XDP_FLAGS_DRV_MODE, NULL);
        if (rc != 0) {
            set_throttle_error("detach stale native throttle XDP program", rc);
            return rc;
        }
        return 1;
    }
    if (program_is_stale_own_copy(handle, opts.skb_prog_id)) {
        rc = bpf_xdp_detach((int)handle->ifindex, XDP_FLAGS_SKB_MODE, NULL);
        if (rc != 0) {
            set_throttle_error("detach stale generic throttle XDP program", rc);
            return rc;
        }
        return 1;
    }
    return 0;
}

static int query_xdp(struct pm_throttle_handle *handle, struct bpf_xdp_query_opts *opts) {
    memset(opts, 0, sizeof(*opts));
    opts->sz = sizeof(*opts);
    int rc = bpf_xdp_query((int)handle->ifindex, 0, opts);
    if (rc != 0)
        set_throttle_error("query attached XDP program", rc);
    return rc;
}

static uint32_t own_netlink_mode(
    struct pm_throttle_handle *handle,
    const struct bpf_xdp_query_opts *opts
) {
    if (opts->drv_prog_id == handle->program_id)
        return PM_THROTTLE_MODE_NATIVE_NETLINK;
    if (opts->skb_prog_id == handle->program_id)
        return PM_THROTTLE_MODE_GENERIC_NETLINK;
    return PM_THROTTLE_MODE_UNKNOWN;
}

static int attach_netlink_fallback(struct pm_throttle_handle *handle) {
    /*
     * Legacy netlink attach is required for generic/SKB XDP on devices where
     * native XDP is unavailable (common for Wi-Fi). With no forced mode flag,
     * libbpf attempts native mode first and falls back to generic/SKB. Never
     * replace a program owned by another component.
     */
    int rc = bpf_xdp_attach(
        (int)handle->ifindex,
        handle->program_fd,
        XDP_FLAGS_UPDATE_IF_NOEXIST,
        NULL
    );
    if (rc == -EEXIST || rc == -EBUSY) {
        int stale = detach_stale_own_netlink(handle);
        if (stale > 0) {
            rc = bpf_xdp_attach(
                (int)handle->ifindex,
                handle->program_fd,
                XDP_FLAGS_UPDATE_IF_NOEXIST,
                NULL
            );
        } else if (stale < 0) {
            return stale;
        }
    }
    if (rc != 0) {
        if (rc == -EEXIST || rc == -EBUSY)
            set_throttle_error("attach throttle XDP program (interface already has an XDP owner)", rc);
        else
            set_throttle_error("attach throttle XDP program", rc);
        return rc;
    }
    handle->netlink_attached = 1;

    struct bpf_xdp_query_opts opts;
    rc = query_xdp(handle, &opts);
    if (rc == 0) {
        handle->attach_mode = own_netlink_mode(handle, &opts);
        if (handle->attach_mode != PM_THROTTLE_MODE_UNKNOWN)
            return 0;
        set_throttle_error("cannot identify throttle XDP attach mode", EPROTO);
        rc = -EPROTO;
    }

    /* Attachment succeeded but ownership/mode discovery failed. Remove only a
     * mode that still points at our exact BPF program id; never detach blindly. */
    if (opts.drv_prog_id == handle->program_id)
        bpf_xdp_detach((int)handle->ifindex, XDP_FLAGS_DRV_MODE, NULL);
    if (opts.skb_prog_id == handle->program_id)
        bpf_xdp_detach((int)handle->ifindex, XDP_FLAGS_SKB_MODE, NULL);
    handle->netlink_attached = 0;
    return rc;
}

static int attach_xdp(struct pm_throttle_handle *handle, struct bpf_program *program) {
    /*
     * Prefer the modern BPF-link lifecycle. On native-XDP-capable NICs the
     * kernel owns the attachment only while this process owns the link FD, so a
     * crash cannot leave the enforcement program attached indefinitely.
     */
    errno = 0;
    struct bpf_link *link = bpf_program__attach_xdp(program, (int)handle->ifindex);
    if (link) {
        handle->link = link;
        handle->attach_mode = PM_THROTTLE_MODE_NATIVE_LINK;
        return 0;
    }
    handle->link = NULL;

    /* Generic/SKB XDP still needs the netlink path on drivers that cannot do
     * native XDP. The loaded BPF program/map are reused for the fallback. */
    return attach_netlink_fallback(handle);
}

static void detach_xdp(struct pm_throttle_handle *handle) {
    if (!handle)
        return;

    if (handle->link) {
        bpf_link__destroy(handle->link);
        handle->link = NULL;
        handle->attach_mode = PM_THROTTLE_MODE_UNKNOWN;
        return;
    }

    if (!handle->netlink_attached || handle->ifindex == 0)
        return;

    struct bpf_xdp_query_opts opts;
    if (query_xdp(handle, &opts) == 0) {
        uint32_t mode = own_netlink_mode(handle, &opts);
        if (mode != PM_THROTTLE_MODE_UNKNOWN) {
            uint32_t flags = mode == PM_THROTTLE_MODE_GENERIC_NETLINK
                ? XDP_FLAGS_SKB_MODE
                : XDP_FLAGS_DRV_MODE;
            int rc = bpf_xdp_detach((int)handle->ifindex, flags, NULL);
            if (rc != 0)
                set_throttle_error("detach throttle XDP program", rc);
        }
    }
    /* If another component replaced the program, deliberately leave it alone. */
    handle->netlink_attached = 0;
    handle->attach_mode = PM_THROTTLE_MODE_UNKNOWN;
}

struct pm_throttle_handle *pm_throttle_open(const char *ifname, const uint8_t *object_data, size_t object_len) {
    if (!ifname || !object_data || object_len == 0) {
        set_throttle_error("invalid throttle loader arguments", EINVAL);
        return NULL;
    }
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        set_throttle_error("throttle interface", errno ? errno : ENODEV);
        return NULL;
    }

    struct pm_throttle_handle *handle = calloc(1, sizeof(*handle));
    if (!handle) {
        set_throttle_error("calloc throttle handle", errno ? errno : ENOMEM);
        return NULL;
    }
    handle->rules_fd = -1;
    handle->program_fd = -1;
    handle->owner_lock_fd = -1;
    handle->ifindex = ifindex;

    int rc = acquire_owner_lock(handle);
    if (rc != 0) {
        free(handle);
        return NULL;
    }

    handle->object = bpf_object__open_mem(object_data, object_len, NULL);
    long object_error = libbpf_get_error(handle->object);
    if (object_error) {
        handle->object = NULL;
        set_throttle_error("bpf_object__open_mem", (int)object_error);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }
    rc = bpf_object__load(handle->object);
    if (rc) {
        set_throttle_error("bpf_object__load", rc);
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }

    struct bpf_program *program = bpf_object__find_program_by_name(handle->object, "bazalt_throttle");
    if (!program) {
        set_throttle_error("find bazalt_throttle program", ENOENT);
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }
    handle->program_fd = bpf_program__fd(program);
    if (handle->program_fd < 0) {
        set_throttle_error("bazalt_throttle program fd", EINVAL);
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }

    rc = load_own_program_id(handle);
    if (rc != 0) {
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }

    struct bpf_map *rules = bpf_object__find_map_by_name(handle->object, "throttle_rules");
    if (!rules) {
        set_throttle_error("find throttle_rules map", ENOENT);
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }
    handle->rules_fd = bpf_map__fd(rules);
    if (handle->rules_fd < 0) {
        set_throttle_error("throttle_rules fd", EINVAL);
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }

    rc = attach_xdp(handle, program);
    if (rc != 0) {
        bpf_object__close(handle->object);
        close(handle->owner_lock_fd);
        free(handle);
        return NULL;
    }
    return handle;
}

int pm_throttle_attach_mode(struct pm_throttle_handle *handle) {
    if (!handle) return PM_THROTTLE_MODE_UNKNOWN;
    return (int)handle->attach_mode;
}

int pm_throttle_set_rule(
    struct pm_throttle_handle *handle,
    const uint8_t addr[4],
    uint32_t prefix_len,
    uint32_t drop_percent,
    uint64_t ttl_seconds
) {
    if (!handle || handle->rules_fd < 0 || !addr || prefix_len > 32 ||
        drop_percent == 0 || drop_percent > 100 || ttl_seconds == 0)
        return -EINVAL;

    struct pm_throttle_key key;
    make_key(&key, addr, prefix_len);
    struct pm_throttle_value value = {
        .drop_percent = drop_percent,
        .reserved = 0,
        .expires_at_ns = 0,
        .seen_packets = 0,
        .seen_bytes = 0,
        .dropped_packets = 0,
        .dropped_bytes = 0,
    };
    uint64_t now = 0;
    int rc = monotonic_ns(&now);
    if (rc != 0) {
        set_throttle_error("clock_gettime(CLOCK_MONOTONIC)", rc);
        return rc;
    }
    uint64_t delta = ttl_seconds > UINT64_MAX / 1000000000ULL
        ? UINT64_MAX
        : ttl_seconds * 1000000000ULL;
    value.expires_at_ns = now > UINT64_MAX - delta ? UINT64_MAX : now + delta;
    if (bpf_map_update_elem(handle->rules_fd, &key, &value, BPF_ANY) != 0) {
        int error = errno;
        set_throttle_error("update throttle rule", error);
        return -error;
    }
    return 0;
}

int pm_throttle_delete_rule(
    struct pm_throttle_handle *handle,
    const uint8_t addr[4],
    uint32_t prefix_len
) {
    if (!handle || handle->rules_fd < 0 || !addr || prefix_len > 32)
        return -EINVAL;
    struct pm_throttle_key key;
    make_key(&key, addr, prefix_len);
    if (bpf_map_delete_elem(handle->rules_fd, &key) != 0) {
        int error = errno;
        if (error != ENOENT)
            set_throttle_error("delete throttle rule", error);
        return -error;
    }
    return 0;
}

int pm_throttle_get_rule_stats(
    struct pm_throttle_handle *handle,
    const uint8_t addr[4],
    uint32_t prefix_len,
    uint64_t *seen_packets,
    uint64_t *seen_bytes,
    uint64_t *dropped_packets,
    uint64_t *dropped_bytes
) {
    if (!handle || handle->rules_fd < 0 || !addr || !seen_packets || !seen_bytes || !dropped_packets || !dropped_bytes)
        return -EINVAL;
    struct pm_throttle_key key;
    make_key(&key, addr, prefix_len);
    struct pm_throttle_value value = {0};
    if (bpf_map_lookup_elem(handle->rules_fd, &key, &value) != 0) {
        int error = errno;
        if (error != ENOENT)
            set_throttle_error("read throttle rule", error);
        return -error;
    }
    *seen_packets = value.seen_packets;
    *seen_bytes = value.seen_bytes;
    *dropped_packets = value.dropped_packets;
    *dropped_bytes = value.dropped_bytes;
    return 0;
}

void pm_throttle_close(struct pm_throttle_handle *handle) {
    if (!handle) return;
    detach_xdp(handle);
    if (handle->object) bpf_object__close(handle->object);
    if (handle->owner_lock_fd >= 0) close(handle->owner_lock_fd);
    free(handle);
}
