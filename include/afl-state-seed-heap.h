#ifndef AFL_STATE_SEED_HEAP_H
#define AFL_STATE_SEED_HEAP_H

#include "types.h" // Include basic types like u32, u8 etc.

// Define the maximum number of seeds to keep track of per state.
// Adjust this based on performance/memory trade-offs. 16 is a reasonable start.
#define MAX_SEEDS_PER_STATE_HEAP 16

// Represents a seed's entry and its score within a specific state's local heap.
// This score reflects how "good" this seed is at reaching this state and
// leading to interesting outcomes *from* this state via mutations.
typedef struct seed_entry_for_state {

  u32    queue_id;  // The unique ID of the seed in afl->queue (e.g., afl->queue_cur->id)
  double score;     // Score of this seed *for this specific state*. Higher is better.

} seed_entry_for_state_t;

// The max-heap structure holding the top seeds for a single state.
// It's a max-heap based on 'score', so the seed deemed "best" for this
// state is always at the root (index 0).
typedef struct seed_heap_for_state {

  seed_entry_for_state_t entries[MAX_SEEDS_PER_STATE_HEAP]; // Fixed-size array for the heap
  u32                    count; // Current number of seeds in this heap (0 to MAX_SEEDS_PER_STATE_HEAP)

} seed_heap_for_state_t;

// Forward declaration of the main state info structure
// Ensure your actual state_info_t definition includes the seed_heap member.
// Example:
/*
typedef struct state_info_s {
    u32                     state_id;    // The transition hash
    double                  total_score; // Score for the main heap of states (state priority)
    seed_heap_for_state_t   seed_heap;   // <<< Internal heap of seeds for this state
    // UT_hash_handle hh; // If using uthash for state_id -> index mapping
    // any other state-specific metadata
} state_info_t;
*/

// Function Prototypes for heap operations (implementation in a .c file)

// Adds a seed or updates its score in the state's seed heap. Handles heap logic.
void upsert_seed_in_state_heap(seed_heap_for_state_t *heap, u32 seed_q_id, double seed_score_increment);

// Returns a pointer to the best seed (highest score) without removing it. Returns NULL if heap is empty.
seed_entry_for_state_t* peek_best_seed_from_state_heap(seed_heap_for_state_t *heap);

// Extracts (gets and removes) the best seed from the state's heap. Returns a dummy entry if empty.
seed_entry_for_state_t extract_best_seed_from_state_heap(seed_heap_for_state_t *heap);


#endif /* AFL_STATE_SEED_HEAP_H */
