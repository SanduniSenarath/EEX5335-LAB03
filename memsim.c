/* memsim.c
 *
 * Simple memory-management simulator for:
 * - TLB (fully associative, LRU)
 * - Single-level page table
 * - Cache (set-associative, LRU)
 * - Main memory (frame allocation, LRU eviction)
 *
 * Compile:
 *   gcc -O2 -std=c11 -o memsim memsim.c
 *
 * Run:
 *   ./memsim addresses.txt
 *
 * addresses.txt format:
 *   R 0x00001234
 *   R 4660
 *
 * Configurable constants below.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <ctype.h>

#define DEBUG 0

/* CONFIGURATION - adjust for testing but keep consistent with report */
#define VADDR_BITS 32
#define PAGE_SIZE 4096U           /* 4 KB */
#define PAGE_OFFSET_BITS 12       /* log2(PAGE_SIZE) */
#define PHYS_MEM_SIZE (64 * 1024) /* 64 KB physical memory for demo */
#define NUM_FRAMES (PHYS_MEM_SIZE / PAGE_SIZE) /* 16 frames */

#define TLB_ENTRIES 16

#define CACHE_SIZE (8 * 1024)  /* 8 KB */
#define CACHE_BLOCK_SIZE 64    /* 64 B block */
#define CACHE_ASSOC 2          /* 2-way set associative */

/* Derived constants */
#define PAGE_ENTRIES (1U << (VADDR_BITS - PAGE_OFFSET_BITS))

/* Cache derived */
#define CACHE_NUM_BLOCKS (CACHE_SIZE / CACHE_BLOCK_SIZE)
#define CACHE_NUM_SETS (CACHE_NUM_BLOCKS / CACHE_ASSOC)
#define CACHE_SET_INDEX_BITS (__builtin_ctz(CACHE_NUM_SETS))
#define CACHE_BLOCK_OFFSET_BITS (__builtin_ctz(CACHE_BLOCK_SIZE))

/* Type definitions */
typedef uint32_t vaddr_t;
typedef uint32_t paddr_t;
typedef uint32_t vpn_t;
typedef uint32_t pfn_t;

/* ---------- Data Structures ---------- */

/* Page Table Entry */
typedef struct {
    int present;
    pfn_t pfn;
    uint64_t last_access; /* for LRU */
} pte_t;

/* TLB Entry (fully associative) */
typedef struct {
    int valid;
    vpn_t vpn;
    pfn_t pfn;
    uint64_t last_access; /* for LRU */
} tlb_entry_t;

/* Physical frame metadata */
typedef struct {
    int used;
    vpn_t vpn; /* which VPN is stored here */
    uint64_t last_access; /* for LRU */
} frame_t;

/* Cache line */
typedef struct {
    int valid;
    uint32_t tag;
    uint64_t last_access; /* for LRU */
    /* For a read-only simulator we don't need data payload */
} cache_line_t;

/* Cache set */
typedef struct {
    cache_line_t *lines; /* size = CACHE_ASSOC */
} cache_set_t;

/* ---------- Globals / Structures ---------- */
static pte_t *page_table = NULL;
static tlb_entry_t tlb[TLB_ENTRIES];
static frame_t frames[NUM_FRAMES];
static uint8_t *phys_mem = NULL; /* simulated physical memory bytes */

static cache_set_t *cache = NULL;

/* Statistics */
static uint64_t stat_accesses = 0;
static uint64_t stat_tlb_hits = 0;
static uint64_t stat_tlb_misses = 0;
static uint64_t stat_page_faults = 0;
static uint64_t stat_page_replacements = 0;
static uint64_t stat_cache_hits = 0;
static uint64_t stat_cache_misses = 0;

/* Logical time counter for LRU */
static uint64_t time_counter = 1;

/* ---------- Utility functions ---------- */

static uint64_t now() {
    return time_counter++;
}

/* find least recently used index in an array of size n */
static int find_lru_index(uint64_t *arr, int n) {
    uint64_t minv = (uint64_t)-1;
    int idx = 0;
    for (int i = 0; i < n; ++i) {
        if (arr[i] < minv) {
            minv = arr[i];
            idx = i;
        }
    }
    return idx;
}

/* ---------- TLB operations ---------- */

static void tlb_init() {
    for (int i = 0; i < TLB_ENTRIES; ++i) {
        tlb[i].valid = 0;
        tlb[i].last_access = 0;
    }
}

/* Lookup VPN in TLB. Returns 1+PFN on hit, 0 on miss (PFN via out param) */
static int tlb_lookup(vpn_t vpn, pfn_t *out_pfn) {
    for (int i = 0; i < TLB_ENTRIES; ++i) {
        if (tlb[i].valid && tlb[i].vpn == vpn) {
            tlb[i].last_access = now();
            *out_pfn = tlb[i].pfn;
            stat_tlb_hits++;
            return 1;
        }
    }
    stat_tlb_misses++;
    return 0;
}

/* Insert mapping to TLB (LRU replacement) */
static void tlb_insert(vpn_t vpn, pfn_t pfn) {
    /* find invalid entry first */
    int free_idx = -1;
    uint64_t times[TLB_ENTRIES];
    for (int i = 0; i < TLB_ENTRIES; ++i) {
        times[i] = tlb[i].last_access;
        if (!tlb[i].valid && free_idx == -1) free_idx = i;
    }
    int insert_idx = (free_idx != -1) ? free_idx : find_lru_index(times, TLB_ENTRIES);
    tlb[insert_idx].valid = 1;
    tlb[insert_idx].vpn = vpn;
    tlb[insert_idx].pfn = pfn;
    tlb[insert_idx].last_access = now();
}

/* ---------- Page table & frame allocation ---------- */

static void page_table_init() {
    page_table = calloc(PAGE_ENTRIES, sizeof(pte_t));
    if (!page_table) {
        fprintf(stderr, "Failed to allocate page table (too large?)\n");
        exit(1);
    }
    for (uint32_t i = 0; i < PAGE_ENTRIES; ++i) {
        page_table[i].present = 0;
        page_table[i].pfn = 0;
        page_table[i].last_access = 0;
    }
}

static void frames_init() {
    for (int i = 0; i < NUM_FRAMES; ++i) {
        frames[i].used = 0;
        frames[i].vpn = 0;
        frames[i].last_access = 0;
    }
}

/* find a free frame, or evict using LRU */
static int allocate_frame(vpn_t vpn) {
    for (int i = 0; i < NUM_FRAMES; ++i) {
        if (!frames[i].used) {
            frames[i].used = 1;
            frames[i].vpn = vpn;
            frames[i].last_access = now();
            return i;
        }
    }
    /* Evict LRU frame */
    uint64_t times[NUM_FRAMES];
    for (int i = 0; i < NUM_FRAMES; ++i) times[i] = frames[i].last_access;
    int evict_idx = find_lru_index(times, NUM_FRAMES);
    /* remove old mapping from page table */
    vpn_t old_vpn = frames[evict_idx].vpn;
    if (page_table[old_vpn].present) {
        page_table[old_vpn].present = 0;
        stat_page_replacements++;
        /* In a real OS, write-back if dirty; here read-only so skip */
    }
    /* install new */
    frames[evict_idx].used = 1;
    frames[evict_idx].vpn = vpn;
    frames[evict_idx].last_access = now();
    return evict_idx;
}

/* Simulate page-in: ensure PTE present and return PFN */
static pfn_t handle_page_fault(vpn_t vpn) {
    stat_page_faults++;
    int f = allocate_frame(vpn);
    /* mark page table */
    page_table[vpn].present = 1;
    page_table[vpn].pfn = f;
    page_table[vpn].last_access = now();
    /* initialize frame memory (optional) */
    memset(phys_mem + (f * PAGE_SIZE), 0, PAGE_SIZE);
    return (pfn_t)f;
}

/* Lookup page table (after TLB miss) */
static pfn_t page_table_lookup(vpn_t vpn) {
    if (page_table[vpn].present) {
        page_table[vpn].last_access = now();
        frames[page_table[vpn].pfn].last_access = now();
        return page_table[vpn].pfn;
    } else {
        return handle_page_fault(vpn);
    }
}

/* ---------- Cache operations ---------- */

static void cache_init() {
    cache = calloc(CACHE_NUM_SETS, sizeof(cache_set_t));
    if (!cache) {
        fprintf(stderr, "Failed to allocate cache sets\n");
        exit(1);
    }
    for (int i = 0; i < CACHE_NUM_SETS; ++i) {
        cache[i].lines = calloc(CACHE_ASSOC, sizeof(cache_line_t));
        if (!cache[i].lines) {
            fprintf(stderr, "Failed to allocate cache lines\n");
            exit(1);
        }
        for (int j = 0; j < CACHE_ASSOC; ++j) {
            cache[i].lines[j].valid = 0;
            cache[i].lines[j].last_access = 0;
        }
    }
}

/* Access physical address in cache. Return 1 if hit, 0 if miss (and simulate load) */
static int cache_access(paddr_t paddr) {
    uint32_t block_offset_mask = (1u << CACHE_BLOCK_OFFSET_BITS) - 1u;
    uint32_t block_addr = paddr >> CACHE_BLOCK_OFFSET_BITS;
    uint32_t set_index = block_addr & (CACHE_NUM_SETS - 1u);
    uint32_t tag = block_addr >> CACHE_SET_INDEX_BITS;

    cache_set_t *set = &cache[set_index];

    /* search lines */
    for (int i = 0; i < CACHE_ASSOC; ++i) {
        if (set->lines[i].valid && set->lines[i].tag == tag) {
            set->lines[i].last_access = now();
            stat_cache_hits++;
            return 1;
        }
    }
    /* miss - bring into cache using LRU replacement */
    stat_cache_misses++;
    uint64_t times[CACHE_ASSOC];
    int free_idx = -1;
    for (int i = 0; i < CACHE_ASSOC; ++i) {
        times[i] = set->lines[i].last_access;
        if (!set->lines[i].valid && free_idx == -1) free_idx = i;
    }
    int insert_idx = (free_idx != -1) ? free_idx : find_lru_index(times, CACHE_ASSOC);
    set->lines[insert_idx].valid = 1;
    set->lines[insert_idx].tag = tag;
    set->lines[insert_idx].last_access = now();
    /* Simulate reading from main memory into cache (no real data copy needed) */
    return 0;
}

/* ---------- Address translation & read handling ---------- */

static void handle_read(vaddr_t vaddr, int verbose) {
    stat_accesses++;
    /* split virtual address */
    vpn_t vpn = vaddr >> PAGE_OFFSET_BITS;
    uint32_t offset = vaddr & (PAGE_SIZE - 1u);
    pfn_t pfn;
    int hit = tlb_lookup(vpn, &pfn);
    if (!hit) {
        /* TLB miss: walk page table */
        pfn = page_table_lookup(vpn);
        tlb_insert(vpn, pfn);
    }
    /* physical address */
    paddr_t paddr = ((paddr_t)pfn << PAGE_OFFSET_BITS) | offset;
    /* cache access (physically indexed) */
    int c_hit = cache_access(paddr);
    /* update frame access time */
    frames[pfn].last_access = now();
    page_table[vpn].last_access = now();
    if (verbose) {
        printf("R 0x%08x -> VPN=%u PFN=%u PADDR=0x%08x Cache:%s TLB:%s\n",
               vaddr, (unsigned)vpn, (unsigned)pfn, paddr,
               c_hit ? "HIT" : "MISS", hit ? "HIT" : "MISS");
    }
}

/* ---------- Initialization and cleanup ---------- */

static void simulator_init() {
    phys_mem = calloc(PHYS_MEM_SIZE, 1);
    if (!phys_mem) {
        fprintf(stderr, "Cannot allocate simulated physical memory\n");
        exit(1);
    }
    tlb_init();
    page_table_init();
    frames_init();
    cache_init();
}

static void simulator_free() {
    if (page_table) free(page_table);
    if (phys_mem) free(phys_mem);
    if (cache) {
        for (int i = 0; i < CACHE_NUM_SETS; ++i) free(cache[i].lines);
        free(cache);
    }
}

/* ---------- Input parsing & main ---------- */

static int parse_hex_or_dec(const char *s, vaddr_t *out) {
    while (isspace((unsigned char)*s)) ++s;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        unsigned long val = strtoul(s, NULL, 16);
        *out = (vaddr_t)val;
        return 1;
    } else {
        unsigned long val = strtoul(s, NULL, 10);
        *out = (vaddr_t)val;
        return 1;
    }
}

int main(int argc, char **argv) {
    FILE *f = stdin;
    int verbose = 0;

    if (argc >= 2) {
        f = fopen(argv[1], "r");
        if (!f) {
            perror("fopen");
            return 1;
        }
    }
    if (argc >= 3) {
        if (strcmp(argv[2], "-v") == 0) verbose = 1;
    }

    /* sanity checks for cache sizes that must be powers of two */
    if ((CACHE_NUM_SETS & (CACHE_NUM_SETS - 1)) != 0) {
        fprintf(stderr, "CACHE_NUM_SETS must be power of two. Reconfigure cache constants.\n");
        return 1;
    }

    simulator_init();

    char op;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (isspace((unsigned char)*p)) ++p;
        if (*p == '\0' || *p == '#') continue;
        if (*p == 'R' || *p == 'r') {
            p++;
            while (isspace((unsigned char)*p)) ++p;
            vaddr_t addr;
            if (parse_hex_or_dec(p, &addr)) {
                handle_read(addr, verbose);
            }
        } else if (*p == 'V' || *p == 'v') {
            /* toggle verbose on/off */
            verbose = 1;
        } else if (*p == 'S' || *p == 's') {
            /* show stats mid-run */
            printf("STAT so far: accesses=%" PRIu64 " tlb_hits=%" PRIu64 " tlb_misses=%" PRIu64
                   " page_faults=%" PRIu64 " cache_hits=%" PRIu64 " cache_misses=%" PRIu64 "\n",
                   stat_accesses, stat_tlb_hits, stat_tlb_misses, stat_page_faults,
                   stat_cache_hits, stat_cache_misses);
        } else {
            /* unknown line - skip */
        }
    }

    /* summary */
    printf("\n--- Simulation Summary ---\n");
    printf("Total memory accesses: %" PRIu64 "\n", stat_accesses);
    printf("TLB hits: %" PRIu64 "  misses: %" PRIu64 "\n", stat_tlb_hits, stat_tlb_misses);
    printf("Page faults: %" PRIu64 "  Page replacements: %" PRIu64 "\n", stat_page_faults, stat_page_replacements);
    printf("Cache hits: %" PRIu64 "  Cache misses: %" PRIu64 "\n", stat_cache_hits, stat_cache_misses);

    simulator_free();
    if (f != stdin) fclose(f);
    return 0;
}
