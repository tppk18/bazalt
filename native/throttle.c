#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
};

static __thread char pm_throttle_error[256];

static void set_throttle_error(const char *what, int error) {
    if (error < 0) error = -error;
    snprintf(pm_throttle_error, sizeof(pm_throttle_error), "%s: %s (%d)", what, strerror(error), error);
}

const char *pm_throttle_last_error(void) {
    return pm_throttle_error;
}

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

    handle->object = bpf_object__open_mem(object_data, object_len, NULL);
    long object_error = libbpf_get_error(handle->object);
    if (object_error) {
        handle->object = NULL;
        set_throttle_error("bpf_object__open_mem", (int)object_error);
        free(handle);
        return NULL;
    }
    int rc = bpf_object__load(handle->object);
    if (rc) {
        set_throttle_error("bpf_object__load", rc);
        bpf_object__close(handle->object);
        free(handle);
        return NULL;
    }

    struct bpf_program *program = bpf_object__find_program_by_name(handle->object, "bazalt_throttle");
    if (!program) {
        set_throttle_error("find bazalt_throttle program", ENOENT);
        bpf_object__close(handle->object);
        free(handle);
        return NULL;
    }
    struct bpf_map *rules = bpf_object__find_map_by_name(handle->object, "throttle_rules");
    if (!rules) {
        set_throttle_error("find throttle_rules map", ENOENT);
        bpf_object__close(handle->object);
        free(handle);
        return NULL;
    }
    handle->rules_fd = bpf_map__fd(rules);
    if (handle->rules_fd < 0) {
        set_throttle_error("throttle_rules fd", EINVAL);
        bpf_object__close(handle->object);
        free(handle);
        return NULL;
    }

    handle->link = bpf_program__attach_xdp(program, (int)ifindex);
    long link_error = libbpf_get_error(handle->link);
    if (link_error) {
        handle->link = NULL;
        set_throttle_error("attach throttle XDP program", (int)link_error);
        bpf_object__close(handle->object);
        free(handle);
        return NULL;
    }
    return handle;
}

int pm_throttle_set_rule(
    struct pm_throttle_handle *handle,
    const uint8_t addr[4],
    uint32_t prefix_len,
    uint32_t drop_percent,
    uint64_t ttl_seconds
) {
    if (!handle || handle->rules_fd < 0 || !addr || prefix_len > 32 || drop_percent == 0 || drop_percent > 100)
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
    if (ttl_seconds != 0) {
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
    }
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
    if (handle->link) bpf_link__destroy(handle->link);
    if (handle->object) bpf_object__close(handle->object);
    free(handle);
}
