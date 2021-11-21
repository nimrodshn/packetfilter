#ifndef __BPF_HELPERS__
#define __BPF_HELPERS__

#define BPF_PRINTK_FMT_MOD

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
#define BUF_SIZE_MAP_NS 256
struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int pinning;
  char namespace[BUF_SIZE_MAP_NS];
};

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;

static int (*bpf_map_update_elem)(void *map, void *key, void *value,unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;

/*
* bpf_trace_printk
* This helper is a "printk()-like" facility for debugging. It
* prints a message defined by format *fmt* (of size *fmt_size*)
* to file *\/sys/kernel/debug/tracing/trace* from DebugFS, if
* available. It can take up to three additional **u64**
* arguments (as an eBPF helpers, the total number of arguments is
* limited to five).
*/
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;

#endif