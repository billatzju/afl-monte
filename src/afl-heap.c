// Function to swap two seed entries in the heap.
#include "afl-heap.h"

// Function to swap two seed entries in the heap.
void swap_seed_entries(seed_entry_t *a, seed_entry_t *b) {
    seed_entry_t temp = *a;
    *a = *b;
    *b = temp;
}

// Max-Heapify function: Fixes the heap property after insertion/deletion.
void max_heapify(state_info_t *state, u32 index) {
    u32 largest = index;
    u32 left = 2 * index + 1;
    u32 right = 2 * index + 2;

    // Compare with left child ('>' for max-heap)
    if (left < state->heap_size &&
        state->top_seeds[left].hit_count > state->top_seeds[largest].hit_count) {
        largest = left;
    }

    // Compare with right child ('>' for max-heap)
    if (right < state->heap_size &&
        state->top_seeds[right].hit_count > state->top_seeds[largest].hit_count) {
        largest = right;
    }

    if (largest != index) {
        swap_seed_entries(&state->top_seeds[index], &state->top_seeds[largest]);
        max_heapify(state, largest);
    }
}

// Insert a new seed into the heap.
void insert_seed(state_info_t *state, u32 seed_id, u32 hit_count) {
    if (state->heap_size == MAX_TOP_SEEDS) {
        state->top_seeds_full = 1;
        // Heap is full. Check if the new seed is better than the *smallest* (root of a *min*-heap,
        // but we've converted this whole thing to use a max-heap, so we compare to see if we need to remove
        // the *smallest*, which is no longer at the root).

        //Find smallest:
        u32 smallest_idx = 0;
        for(u32 i = 1; i < MAX_TOP_SEEDS; ++i){
            if(state->top_seeds[i].hit_count < state->top_seeds[smallest_idx].hit_count){
                smallest_idx = i;
            }
        }
        if (hit_count > state->top_seeds[smallest_idx].hit_count) {
            // Replace the smallest with the new seed.
            state->top_seeds[smallest_idx].seed_id = seed_id;
            state->top_seeds[smallest_idx].hit_count = hit_count;
            // Heapify to maintain the max-heap property.
            max_heapify(state, smallest_idx); //Corrected to start at smallest_idx
        }
    } else {
        // Add the new seed to the end of the heap.
        u32 i = state->heap_size;
        state->top_seeds[i].seed_id = seed_id;
        state->top_seeds[i].hit_count = hit_count;
        state->heap_size++;

        // Fix the max-heap property by "bubbling up" the new element.
        // Parent comparison: (i-1)/2, correct for both even and odd i
        while (i != 0 && state->top_seeds[(i - 1) / 2].hit_count < state->top_seeds[i].hit_count) { // '<' for max-heap
            swap_seed_entries(&state->top_seeds[i], &state->top_seeds[(i - 1) / 2]);
            i = (i - 1) / 2;
        }
        if(state->heap_size == MAX_TOP_SEEDS) state->top_seeds_full = 1;
    }
}
//update the hit count of a seed if it is presented in the heap
u8 update_seed_hits(state_info_t *state, u32 seed_id){
    u32 index = (u32)-1; // Initialize to an invalid index
    for(u32 i = 0; i < state->heap_size; i++){
      if(state->top_seeds[i].seed_id == seed_id){
        index = i;
        break;
      }
    }
    // return if it is not present in the heap
    if(index == (u32)-1){
        return 0;
        }
    state->top_seeds[index].hit_count += 1;
     // Restore max-heap property after increasing hit_count.  We need to
    // "bubble up" the modified element, not heapify from the root.
    while (index != 0 && state->top_seeds[(index - 1) / 2].hit_count < state->top_seeds[index].hit_count) {
        swap_seed_entries(&state->top_seeds[index], &state->top_seeds[(index - 1) / 2]);
        index = (index - 1) / 2;
    }
    return 1;
}

// Function to check if a seed is already in the heap.
int seed_in_heap(state_info_t *state, u32 seed_id) {
  for (u32 i = 0; i < state->heap_size; i++) {
    if (state->top_seeds[i].seed_id == seed_id) {
      return 1; // Found
    }
  }
  return 0; // Not found
}