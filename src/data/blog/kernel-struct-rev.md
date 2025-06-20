---
title: Partial recovery of Linux kernel structure layouts
author: jxuanli
pubDatetime: 2025-06-18T10:03:00.000+00:00
slug: linux-kernel-structure-layouts-partial-recovery
featured: false
draft: false
tags:
  - kernel
  - linux
  - reverse engineering
description: "Recovering partial layouts of kernel structures associated with the SLUB and buddy allocators for kernel pwning"
timezone: "America/Vancouver"
---

## Introduction

CTF kernel challenge authors sometimes do not include uncompressed Linux kernel images (`vmlinux`) that provide type information but rather compressed images with only locations of kernel functions and global data (`kallsyms`). Unfortunately, type information is usually lost during compression and cannot be recovered with tools such as [`vmlinux-to-elf`](https://github.com/marin-m/vmlinux-to-elf). The `d3kheap2` from `D^3CTF 2025` is one example among many. It only allows an array of kernel objects in a dedicated cache (for our purposes) to be freed exactly twice. This hints at the cross-cache technique to bypass cache isolation by carefully crafting kernel heap states. Unable to use commands such as `buddydump` and `slab` provided by `pwndbg` to examine the states of the page and SLUB allocators, I became a bit frustrated because I developed (or improved) those two commands specifically for challenges that involve the kernel heap and the cross-cache technique. The commands were unusable because they access individual fields by name, and the added symbol file did not contain type information. So, I decided to make a change.

This seemed intimidating and borderline impossible at first because kernel structure layouts change over time and depend on kernel configurations. Regardless, I wanted those two commands to work without being provided with type information. It turned out to be much easier than expected with some clever engineering choices.

My implementation handles build configurations and reconciles between different kernel versions with compiler directives. However, some configurations are difficult to determine. Some structures also have nested substructures whose sizes are required for computing the offsets of relevant fields. Correct offsets are required for accessing fields by name. To address those issues, I observed that only a subset of fields in those structures are relevant. So, I decided to only recover the offsets of those fields for complex structures, which significantly eased the task. Since a few folks I talked to were interested in my solution to this problem, I am detailing some of the above ideas in hopes of leading to a generic way of extracting kernel type information. The below discussion applies to all Linux kernel v5 and v6 releases to date.

## `buddydump`

The `buddydump` command displays the internal states of the buddy (page) allocator. It helps identify recycled pages ready to be reused for another cache after allocating and freeing many objects in a cache containing the vulnerable object. Notably, it depends on the `node_data` and the layout of `struct zone`.

```c
struct free_area {
	struct list_head free_list[MIGRATE_TYPES];
	unsigned long nr_free;
};

struct zone {
    char _pad1[pad1_sz];
    struct pglist_data *zone_pgdat;
#ifdef BEFORE_V5_14
    struct per_cpu_pageset __percpu *pageset; // PCP list
#else
    struct per_cpu_pages __percpu *per_cpu_pageset; // PCP list
#endif
    char _pad2[pad2_sz]; // includes cache line padding
    char* name;
    char _pad3[pad3_sz];
    struct free_area free_area[MAX_ORDER]; // MAX_ORDER == 11 for all v5 and v6 releases by the time of writing
    char _pad4[pad4_sz];
};

struct pglist_data {
	struct zone node_zones[MAX_NR_ZONES];
  // ...
};

struct pglist_data *node_data[MAX_NUMNODES];
```
Because `node_data` is global and `node_zones` is the first field of `pglist_data`, the starting address of the first `struct zone` can be easily extracted. Next, four padding sizes need to be determined. `zone_pgdat` is the first kernel pointer within `struct zone` so `pad1_sz` is the distance between the start and the location of `zone_pgdat`. `pad2_sz` is determined by finding a kernel pointer to a string that is one of six possible zone names. Computing `pad3_sz` involves observing that the `zone.free_area[0].free_list.next` always succeeds a padding that is filled with zero. The padding is used to divide the structure into a read-mostly area and a write-intensive area for caching. Therefore, `pad3_sz` can be computed after finding the first kernel pointer succeeding the name pointer that is preceded by zero. Lastly, since `node_zones` is a static array and type information is not provided, the size of `struct zone` is needed to traverse all zones. This is accomplished by computing the difference between the locations of `zone_pgdat` in the first and second `struct zone`. The location of the second `zone_pgdat` can be found by searching the first kernel pointer after the last free area. Those ideas are illustrated with a memory dump provided below.

```
pwndbg> x/10gx &node_data
0xffffffffb1550c30:     0xffff9b8207e08940      0x0000000000000000 # there is only one node
0xffffffffb1550c40:     0x0000000000000000      0x0000000000000000
0xffffffffb1550c50:     0x0000000000000000      0x0000000000000000
0xffffffffb1550c60:     0x0000000000000000      0x0000000000000000
0xffffffffb1550c70:     0x0000000000000000      0x0000000000000000
pwndbg> x/170gx 0xffff9b8207e08940
0xffff9b8207e08940:     0x0000000000000034      0x0000000000000041 # node_data[0].node_zones[0]
0xffff9b8207e08950:     0x000000000000004e      0x000000000000005b
0xffff9b8207e08960:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08970:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08980:     0x0000000000000043      0x0000000000000043
0xffff9b8207e08990:     0x0000000000000043      0x0000000000000000
0xffff9b8207e089a0:     0xffff9b8207e08940      0x0000000000031a80 # node_data[0].node_zones[0].zone_pgdat followed by PCP list
0xffff9b8207e089b0:     0x0000000000031a20      0x000001e000000041
0xffff9b8207e089c0:     0x0000000000000001      0x0000000000000001
0xffff9b8207e089d0:     0x0000000000000f00      0x0000000000000fff
0xffff9b8207e089e0:     0x0000000000000f9e      0xffffffffb075dde3
0xffff9b8207e089f0:     0x0000000000000001      0x0000000000000000
0xffff9b8207e08a00:     0xffff9b8207e08a00      0xffff9b8207e08a00 # first free area
0xffff9b8207e08a10:     0xffff9b8207e08a10      0xffff9b8207e08a10
0xffff9b8207e08a20:     0xffff9b8207e08a20      0xffff9b8207e08a20
0xffff9b8207e08a30:     0xffff9b8207e08a30      0xffff9b8207e08a30
(... free area lists)
0xffff9b8207e08cd0:     0xffff9b8207e08cd0      0xffff9b8207e08cd0 # last free area
0xffff9b8207e08ce0:     0xffffd360c0010008      0xffffd360c0030008
0xffff9b8207e08cf0:     0xffff9b8207e08cf0      0xffff9b8207e08cf0
0xffff9b8207e08d00:     0xffff9b8207e08d00      0xffff9b8207e08d00
0xffff9b8207e08d10:     0x0000000000000003      0x0000000000000000 # rest of node_zones[0]
0xffff9b8207e08d20:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08d30:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08d40:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08d50:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08d60:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08d70:     0x0000000000000000      0x0000010000000000
0xffff9b8207e08d80:     0x0000000000000f00      0x0000000000000000
0xffff9b8207e08d90:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08da0:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08db0:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08dc0:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08dd0:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08de0:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08df0:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08e00:     0x00000000000000ed      0x0000000000000128 # node_data[0].node_zones[1]
0xffff9b8207e08e10:     0x0000000000000163      0x000000000000019e
0xffff9b8207e08e20:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08e30:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08e40:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08e50:     0x0000000000000000      0x0000000000000000
0xffff9b8207e08e60:     0xffff9b8207e08940      0x0000000000031bc0 # node_data[0].node_zones[1].zone_pgdat followed by PCP list
0xffff9b8207e08e70:     0x0000000000031b80      0x0000087200000128
0xffff9b8207e08e80:     0x0000000000000003      0x0000000000001000
```

## `slab`

`slab` is a command that displays the information of the SLUB allocator. Notably, it depends on the layout of `struct kmem_cache`.

```c
struct kmem_cache_node {
    spinlock_t list_lock;
    unsigned long nr_partial; // offset = 8
    struct list_head partial;
};
struct kmem_cache {
#if !defined(CONFIG_SLUB_TINY) || defined(BEFORE_V6_2)
    struct kmem_cache_cpu *cpu_slab;
#endif
    /* Used for retrieving partial slabs, etc. */
    slab_flags_t flags;
    unsigned long min_partial;
    unsigned int size; /* Object size including metadata */
    unsigned int object_size; /* Object size without metadata */
    struct reciprocal_value reciprocal_size;
    unsigned int offset; /* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
    /* Number of per cpu partial objects to keep around */
    unsigned int cpu_partial;
    /* Number of per cpu partial slabs to keep around */
    unsigned int cpu_partial_slabs;
#endif
    struct kmem_cache_order_objects oo;
    /* Allocation and freeing of slabs */
    struct kmem_cache_order_objects min;
#ifdef BEFORE_V5_19
    struct kmem_cache_order_objects max;
#endif
    gfp_t allocflags; /* gfp flags to use on each alloc */
    int refcount; /* Refcount for slab cache destroy */
    void (*ctor)(void *object); /* Object constructor */
    unsigned int inuse; /* Offset to metadata */
    unsigned int align; /* Alignment */
    unsigned int red_left_pad; /* Left redzone padding size */
    const char *name; /* Name (only for display!) */
    struct list_head list; /* List of slab caches */

    char _pad5[pad5_sz]; // collapse the struct(s) that are version-dependent and complex
#ifdef CONFIG_SLAB_FREELIST_HARDENED
    unsigned long random;
#endif
#ifdef CONFIG_NUMA
    unsigned int remote_node_defrag_ratio;
#endif
#ifdef CONFIG_SLAB_FREELIST_RANDOM
    unsigned int *random_seq;
#endif
#ifdef CONFIG_KASAN_GENERIC
    char _pad6[8]; // the kasan_cache struct includes only 2 int's
#endif
#if defined(BEFORE_V6_2) || defined(CONFIG_HARDENED_USERCOPY)
    unsigned int useroffset; /* Usercopy region offset */
    unsigned int usersize; /* Usercopy region size */
#endif
    // make sure it has at least that many, sufficient for us
    struct kmem_cache_node *node[NUM_NUMA_NODES]; // can be extracted
};
```

As shown above, the status of several configuration options needs to be determined. This has been demonstrated by [`kernelinit`](https://github.com/Myldero/kernelinit). For instance, `CONFIG_SLAB_FREELIST_RANDOM` is set if the function name `init_cache_random_seq` is present. Next, `pad5_sz` needs to be computed. Its purpose is to ignore irrelevant fields that contain complex structures and are version-dependent while ensuring the offsets of relevant fields are correct. Achieving this involves computing the distance between the name pointer and the first `struct kmem_cache_node` pointer. The location of the pointer is determined by observing the unique layout of `struct kmem_cache_node`. It has an unsigned long followed by two kernel pointers and is found by examining memory pointed to by valid kernel pointers. This distance serves as an upper bound on `pad5_sz` and is adjusted based on enabled kernel configurations detected through the method mentioned previously.

## Conclusion

Implementing the ideas discussed in this post, I was able to debug the states of the page and SLUB allocators and solve `d3kheap2`. The implementation relied on a thorough analysis of the memory layout signature of relevant kernel object fields. See [#3116](https://github.com/pwndbg/pwndbg/pull/3116) for the full implementation.

