// afl-heap.h - Corrected for Max-Heap based on hit_count

#ifndef _HAVE_AFL_HEAP_H // Add include guards
#define _HAVE_AFL_HEAP_H

#include "types.h"      // For u8, u32, u64
#include "uthash.h"     // Included here, but primarily for the state map elsewhere

#define MAX_TOP_SEEDS 10

typedef struct seed_entry {
    u32 seed_id;
    u32 hit_count;
} seed_entry_t;

// Structure for the uthash map (state_id -> heap_index) - belongs with fuzzer state
typedef struct state_index_map_entry {
    u32 state_id;             /* key */
    u32 heap_index;           /* value */
    UT_hash_handle hh;        /* makes this structure hashable */
} state_index_map_entry_t;

// Main state structure (includes the seed max-heap)
typedef struct state_info {
    u32             state_id;
    double             total_score;  // For the *state* max-heap
    u32             hit_count; // Overall state hit_count - NOTE: Consider if needed separately from seed heap logic
    seed_entry_t    top_seeds[MAX_TOP_SEEDS]; // Array managed as a *seed* max-heap
    u32             heap_size;    // Current size of the *seed* max-heap
    u8              top_seeds_full; // Flag for the *seed* max-heap
} state_info_t;

// --- Function Prototypes for Seed Max-Heap Operations ---

/* Swaps two seed_entry_t structures. */
void swap_seed_entries(seed_entry_t *a, seed_entry_t *b);

/* Max-Heapify function (based on hit_count): Fixes the max-heap property
   for the top_seeds array within a state_info_t structure after modification. */
void max_heapify(state_info_t *state, u32 index); // Renamed from min_heapify

/* Inserts a new seed into the seed max-heap within a state_info_t structure.
   Handles replacement if the heap is full and the new seed is better (higher hit_count)
   than the worst existing seed (lowest hit_count). */
void insert_seed(state_info_t *state, u32 seed_id, u32 hit_count);

/* Updates the hit count of a seed if present in the seed max-heap and restores
   the heap property. Returns 1 if updated, 0 if seed not found. */
u8 update_seed_hits(state_info_t *state, u32 seed_id);

/* Checks if a seed_id is currently present in the seed max-heap.
   Returns 1 if found, 0 otherwise. */
int seed_in_heap(state_info_t *state, u32 seed_id);


// --- Function Prototypes for State Max-Heap Operations (Example, likely belong elsewhere) ---
/* These operate on the fsrv->state_info array, which is a max-heap based on total_score */
/* You'll need appropriate includes like afl-fuzz.h if these go here */
/*
struct afl_forkserver; // Forward declaration if needed

void swap_state_info(struct afl_forkserver *fsrv, u32 index_a, u32 index_b);
void state_max_heapify(struct afl_forkserver *fsrv, u32 index);
// ... other state heap function prototypes ...
*/

#endif /* _HAVE_AFL_HEAP_H */