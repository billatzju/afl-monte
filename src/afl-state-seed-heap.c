#include "afl-fuzz.h" // Include main header for types, afl_state_t etc.
// Potentially include the header file where the structs above are defined, e.g.:
#include "afl-state-seed-heap.h"

/*
-------------------------------------------------------
 Internal Seed Heap Management for State Prioritization
-------------------------------------------------------
 These functions manage the max-heap (`seed_heap_for_state_t`)
 stored within each `state_info_t`. This heap keeps track of
 the seeds from the main queue (`afl->queue`) that have proven
 most effective (highest score) at reaching the associated state
 and leading to interesting behavior thereafter.
*/

// --- Helper Functions ---

/**
 * @brief Swaps two seed entries in the heap array.
 * @param a Pointer to the first entry.
 * @param b Pointer to the second entry.
 */
static inline void seed_heap_swap_entries(seed_entry_for_state_t *a, seed_entry_for_state_t *b) {
    seed_entry_for_state_t temp = *a;
    *a = *b;
    *b = temp;
}

/**
 * @brief Restores the max-heap property by moving an element up the heap.
 * Assumes score is double, higher score is better.
 * @param heap Pointer to the seed heap.
 * @param idx Index of the element to start heapifying up from.
 */
static void seed_max_heapify_up(seed_heap_for_state_t *heap, u32 idx) {
    // Check bounds and if already at root
    if (idx == 0 || idx >= heap->count) return;

    u32 parent_idx = (idx - 1) / 2;

    // While the current node's score is greater than its parent's score
    while (idx > 0 && heap->entries[idx].score > heap->entries[parent_idx].score) {
        // Swap current node with parent
        seed_heap_swap_entries(&heap->entries[idx], &heap->entries[parent_idx]);
        // Move up to the parent's index
        idx = parent_idx;
        // Stop if we reached the root
        if (idx == 0) break;
        // Calculate the new parent index
        parent_idx = (idx - 1) / 2;
    }
}

/**
 * @brief Restores the max-heap property by moving an element down the heap.
 * Assumes score is double, higher score is better.
 * @param heap Pointer to the seed heap.
 * @param idx Index of the element to start heapifying down from (usually 0 after extraction).
 */
static void seed_max_heapify_down(seed_heap_for_state_t *heap, u32 idx) {
    u32 largest = idx;          // Initialize largest as root
    u32 left_child_idx = 2 * idx + 1;
    u32 right_child_idx = 2 * idx + 2;

    // Check if left child exists and is larger than current largest
    if (left_child_idx < heap->count && heap->entries[left_child_idx].score > heap->entries[largest].score) {
        largest = left_child_idx;
    }

    // Check if right child exists and is larger than current largest
    if (right_child_idx < heap->count && heap->entries[right_child_idx].score > heap->entries[largest].score) {
        largest = right_child_idx;
    }

    // If largest is not the current node, swap and recursively heapify down
    if (largest != idx) {
        seed_heap_swap_entries(&heap->entries[idx], &heap->entries[largest]);
        seed_max_heapify_down(heap, largest);
    }
}

/**
 * @brief Finds the index of the seed with the minimum score in the heap.
 * Necessary when the heap is full and we need to decide whether to replace an element.
 * @param heap Pointer to the seed heap.
 * @return Index of the minimum score element, or -1 if heap is empty.
 */
static s32 find_min_score_idx_in_max_heap(seed_heap_for_state_t *heap) {
    if (heap->count == 0) return -1;

    s32 min_idx = 0;
    for (u32 i = 1; i < heap->count; ++i) {
        if (heap->entries[i].score < heap->entries[min_idx].score) {
            min_idx = i;
        }
    }
    return min_idx;
}


// --- Public API Functions ---

/**
 * @brief Adds a seed to the state's seed heap or updates its score if it already exists.
 * If the heap is full, it potentially replaces the seed with the lowest score.
 *
 * @param heap Pointer to the specific state's seed_heap_for_state_t.
 * @param seed_q_id The unique ID of the seed (from afl->queue).
 * @param seed_score_increment The positive score change to apply to this seed for this state based on the current execution's outcome.
 */
void upsert_seed_in_state_heap(seed_heap_for_state_t *heap, u32 seed_q_id, double seed_score_increment) {

    // We only add/update scores based on positive contributions.
    // Negative scores (decay) should primarily affect the main state score, not the seed's rank within a state.
    if (seed_score_increment <= 0) { return; }

    s32 existing_entry_idx = -1;

    // Check if the seed already exists in this state's heap
    for (u32 i = 0; i < heap->count; ++i) {
        if (heap->entries[i].queue_id == seed_q_id) {
            existing_entry_idx = i;
            break;
        }
    }

    if (existing_entry_idx != -1) {
        // --- Seed exists: Update score and re-heapify ---
        heap->entries[existing_entry_idx].score += seed_score_increment;
        // Score increased, so we only need to heapify upwards.
        seed_max_heapify_up(heap, existing_entry_idx);

    } else {
        // --- Seed is new to this state's heap ---
        // The initial score for a new seed in this state's context.
        // Could just be the increment, or a base value + increment. Let's use increment.
        double initial_score_for_new_seed = seed_score_increment;

        if (heap->count < MAX_SEEDS_PER_STATE_HEAP) {
            // --- Heap has space: Add the new seed ---
            heap->entries[heap->count].queue_id = seed_q_id;
            heap->entries[heap->count].score = initial_score_for_new_seed;
            heap->count++;
            // Heapify the new element up from the bottom
            seed_max_heapify_up(heap, heap->count - 1);

        } else {
            // --- Heap is full: Try to replace the lowest-scoring seed ---
            s32 min_score_idx = find_min_score_idx_in_max_heap(heap);

            // Should always find a min_idx if heap->count == MAX_SEEDS_PER_STATE_HEAP > 0
            if (min_score_idx != -1 && initial_score_for_new_seed > heap->entries[min_score_idx].score) {
                // New seed is better than the worst one currently in the heap. Replace it.
                heap->entries[min_score_idx].queue_id = seed_q_id;
                heap->entries[min_score_idx].score = initial_score_for_new_seed;

                // The replaced element might violate heap property upwards.
                seed_max_heapify_up(heap, min_score_idx);
                // It's also possible (though less likely if replacing min) that it violates downwards.
                // A sift-down might be needed too, but sift-up is the primary concern here.
                // For robustness, could call heapify_down as well, though often redundant after sift-up.
                 seed_max_heapify_down(heap, min_score_idx);
            }
            // else: New seed isn't good enough to make it into the full heap. Discard.
        }
    }
}


/**
 * @brief Returns a pointer to the seed entry with the highest score in the state's heap.
 * Does not remove the entry.
 *
 * @param heap Pointer to the seed heap.
 * @return Pointer to the best seed_entry_for_state_t, or NULL if the heap is empty.
 */
seed_entry_for_state_t* peek_best_seed_from_state_heap(seed_heap_for_state_t *heap) {
    if (heap == NULL || heap->count == 0) {
        return NULL;
    }
    // In a max-heap, the best element is always at the root (index 0).
    return &heap->entries[0];
}


/**
 * @brief Extracts (gets and removes) the seed entry with the highest score from the state's heap.
 *
 * @param heap Pointer to the seed heap.
 * @return The best seed_entry_for_state_t. If the heap was empty, returns an entry with score < 0 as an indicator.
 */
seed_entry_for_state_t extract_best_seed_from_state_heap(seed_heap_for_state_t *heap) {
    if (heap == NULL || heap->count == 0) {
        seed_entry_for_state_t empty_entry = {0, -1.0}; // Indicate empty/invalid
        return empty_entry;
    }

    // The best entry is at the root
    seed_entry_for_state_t best_entry = heap->entries[0];

    // Replace the root with the last element
    heap->entries[0] = heap->entries[heap->count - 1];
    heap->count--; // Decrease the count

    // Restore the max-heap property by sifting down from the root
    if (heap->count > 0) {
        seed_max_heapify_down(heap, 0);
    }

    return best_entry;
}

