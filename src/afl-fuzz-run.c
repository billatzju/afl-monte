/*
   american fuzzy lop++ - target execution related routines
   --------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com> and
                        Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */



#include "afl-fuzz.h"
#include "sharedmem.h"
#include "afl-hash.h"
#include "afl-heap.h"
#include <sys/time.h>
#include <signal.h>
#include <limits.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

#include "cmplog.h"
#include "afl-state-seed-heap.h"
#include "asanfuzz.h"
#ifdef PROFILING
u64 time_spent_working = 0;
#endif

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot)) fuzz_run_target(afl_state_t      *afl,
                                                       afl_forkserver_t *fsrv,
                                                       u32 timeout) {

#ifdef PROFILING
  static u64      time_spent_start = 0;
  struct timespec spec;
  if (time_spent_start) {

    u64 current;
    clock_gettime(CLOCK_REALTIME, &spec);
    current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
    time_spent_working += (current - time_spent_start);

  }

#endif

  fsrv_run_result_t res = afl_fsrv_run_target(fsrv, timeout, &afl->stop_soon);

#ifdef __AFL_CODE_COVERAGE
  if (unlikely(!fsrv->persistent_trace_bits)) {

    // On the first run, we allocate the persistent map to collect coverage.
    fsrv->persistent_trace_bits = (u8 *)malloc(fsrv->map_size);
    memset(fsrv->persistent_trace_bits, 0, fsrv->map_size);

  }

  for (u32 i = 0; i < fsrv->map_size; ++i) {

    if (fsrv->persistent_trace_bits[i] != 255 && fsrv->trace_bits[i]) {

      fsrv->persistent_trace_bits[i]++;

    }

  }

#endif

  /* If post_run() function is defined in custom mutator, the function will be
     called each time after AFL++ executes the target program. */

  if (unlikely(afl->custom_mutators_count)) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (unlikely(el->afl_custom_post_run)) {

        el->afl_custom_post_run(el->data);

      }

    });

  }

#ifdef PROFILING
  clock_gettime(CLOCK_REALTIME, &spec);
  time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
#endif

  return res;

}

/* Write modified data to file for testing. If afl->fsrv.out_file is set, the
   old file is unlinked and a new one is created. Otherwise, afl->fsrv.out_fd is
   rewound and truncated. */

u32 __attribute__((hot)) write_to_testcase(afl_state_t *afl, void **mem,
                                           u32 len, u32 fix) {

  u8 sent = 0;

  if (unlikely(afl->custom_mutators_count)) {

    ssize_t new_size = len;
    u8     *new_mem = *mem;
    u8     *new_buf = NULL;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf || new_size <= 0)) {

          new_size = 0;
          new_buf = new_mem;
          // FATAL("Custom_post_process failed (ret: %lu)", (long
          // unsigned)new_size);

        } else {

          new_mem = new_buf;

        }

      }

    });

    if (unlikely(!new_size)) {

      // perform dummy runs (fix = 1), but skip all others
      if (fix) {

        new_size = len;

      } else {

        return 0;

      }

    }

    if (unlikely(new_size < afl->min_length && !fix)) {

      new_size = afl->min_length;

    } else if (unlikely(new_size > afl->max_length)) {

      new_size = afl->max_length;

    }

    if (new_mem != *mem && new_mem != NULL && new_size > 0) {

      new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), new_size);
      if (unlikely(!new_buf)) { PFATAL("alloc"); }
      memcpy(new_buf, new_mem, new_size);

      /* if AFL_POST_PROCESS_KEEP_ORIGINAL is set then save the original memory
         prior post-processing in new_mem to restore it later */
      if (unlikely(afl->afl_env.afl_post_process_keep_original)) {

        new_mem = *mem;

      }

      *mem = new_buf;
      afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));

    }

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_fuzz_send) {

        if (!afl->afl_env.afl_custom_mutator_late_send) {

          el->afl_custom_fuzz_send(el->data, *mem, new_size);

        } else {

          afl->fsrv.custom_input = *mem;
          afl->fsrv.custom_input_len = new_size;

        }

        sent = 1;

      }

    });

    if (likely(!sent)) {

      /* everything as planned. use the potentially new data. */
      afl_fsrv_write_to_testcase(&afl->fsrv, *mem, new_size);

    }

    if (likely(!afl->afl_env.afl_post_process_keep_original)) {

      len = new_size;

    } else {

      /* restore the original memory which was saved in new_mem */
      *mem = new_mem;
      afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));

    }

  } else {                                   /* !afl->custom_mutators_count */

    if (unlikely(len < afl->min_length && !fix)) {

      len = afl->min_length;

    } else if (unlikely(len > afl->max_length)) {

      len = afl->max_length;

    }

    /* boring uncustom. */
    afl_fsrv_write_to_testcase(&afl->fsrv, *mem, len);

  }

#ifdef _AFL_DOCUMENT_MUTATIONS
  s32  doc_fd;
  char fn[PATH_MAX];
  snprintf(fn, PATH_MAX, "%s/mutations/%09u:%s", afl->out_dir,
           afl->document_counter++,
           describe_op(afl, 0, NAME_MAX - strlen("000000000:")));

  if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION)) >=
      0) {

    if (write(doc_fd, *mem, len) != len)
      PFATAL("write to mutation file failed: %s", fn);
    close(doc_fd);

  }

#endif

  return len;

}

/**
 * @brief Swaps two state_info_t elements in the heap array AND updates the
 * state_id -> heap_index map.
 *
 * @param fsrv Pointer to the forkserver structure containing the heap and map.
 * @param index_a Index of the first element to swap.
 * @param index_b Index of the second element to swap.
 */
static inline void swap_state_info(afl_forkserver_t *fsrv, u32 index_a, u32 index_b) {

    if (index_a == index_b || index_a >= fsrv->state_heap_size || index_b >= fsrv->state_heap_size) return;

    //FILE *score_rec = fopen("swapping","a");

    // Get state IDs *before* swapping content
    u32 state_id_a = fsrv->state_info[index_a].state_id;
    u32 state_id_b = fsrv->state_info[index_b].state_id;
    //fprintf(score_rec,"index 1 in the heap stores state id: %d, index 2 in the heap stores state id in the heap : %d\n", state_id_a, state_id_b);

    // 1. Perform the swap in the main state_info array
    state_info_t temp = fsrv->state_info[index_a];
    fsrv->state_info[index_a] = fsrv->state_info[index_b];
    fsrv->state_info[index_b] = temp;
    // fprintf(score_rec,"index 1: %d, index 2: %d\n", index_a, index_b);
    // fprintf(score_rec,"attempting to swapping in the state_info heap, the state_id 1 now becomes %d, state_id 2 now becomes %d\n", 
      // fsrv->state_info[index_a].state_id, fsrv->state_info[index_b].state_id);


    // 2. Update the hash map to reflect the new indices
    //    Use state_map_upsert (which handles insert or update)
    state_map_upsert(fsrv, state_id_a, index_b); // state_a is now at index_b
    state_map_upsert(fsrv, state_id_b, index_a); // state_b is now at index_a
    u32 index;

    state_map_lookup(fsrv, state_id_a, &index);
    u32 ind1; 
    state_map_lookup(fsrv, state_id_b, &ind1);
    // fprintf(score_rec,"index 1: %d score:%.10f, index 2: %d, score:%.10f\n", index,fsrv->state_info[index].total_score, ind1, fsrv->state_info[ind1].total_score);
    // fclose(score_rec);

    
}


/**
 * @brief Restores the max-heap property for the state heap (based on total_score)
 * starting from a given index (sift-down). Assumes total_score is double.
 *
 * @param fsrv Pointer to the forkserver structure.
 * @param index The index to start heapifying from.
 */
void state_max_heapify(afl_forkserver_t *fsrv, u32 index) {
    u32 largest = index;
    u32 left = 2 * index + 1;
    u32 right = 2 * index + 2;

    // Use correct bound: fsrv->state_heap_size
    // Compare double scores
    if (left < fsrv->state_heap_size &&
        fsrv->state_info[left].total_score > fsrv->state_info[largest].total_score) {
        largest = left;
    }

    // Use correct bound: fsrv->state_heap_size
    // Compare double scores
    if (right < fsrv->state_heap_size &&
        fsrv->state_info[right].total_score > fsrv->state_info[largest].total_score) {
        largest = right;
    }

    if (largest != index) {
        // Use the swap function that updates the hash map
        swap_state_info(fsrv, index, largest);
        // Recursively heapify the affected sub-tree
        state_max_heapify(fsrv, largest);
    }
}

/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(afl_state_t *afl, u8 *mem, u32 len, u32 skip_at,
                           u32 skip_len) {

  s32 fd = afl->fsrv.out_fd;
  u32 tail_len = len - skip_at - skip_len;

  /*
  This memory is used to carry out the post_processing(if present) after copying
  the testcase by removing the gaps. This can break though
  */
  u8 *mem_trimmed = afl_realloc(AFL_BUF_PARAM(out_scratch), len - skip_len + 1);
  if (unlikely(!mem_trimmed)) { PFATAL("alloc"); }

  ssize_t new_size = len - skip_len;
  u8     *new_mem = mem;

  bool post_process_skipped = true;

  if (unlikely(afl->custom_mutators_count)) {

    u8 *new_buf = NULL;
    new_mem = mem_trimmed;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_post_process) {

        // We copy into the mem_trimmed only if we actually have custom mutators
        // *with* post_processing installed

        if (post_process_skipped) {

          if (skip_at) { memcpy(mem_trimmed, (u8 *)mem, skip_at); }

          if (tail_len) {

            memcpy(mem_trimmed + skip_at, (u8 *)mem + skip_at + skip_len,
                   tail_len);

          }

          post_process_skipped = false;

        }

        new_size =
            el->afl_custom_post_process(el->data, new_mem, new_size, &new_buf);

        if (unlikely(!new_buf && new_size <= 0)) {

          new_size = 0;
          new_buf = new_mem;
          // FATAL("Custom_post_process failed (ret: %lu)", (long
          // unsigned)new_size);

        } else {

          new_mem = new_buf;

        }

      }

    });

  }

  if (likely(afl->fsrv.use_shmem_fuzz)) {

    if (!post_process_skipped) {

      // If we did post_processing, copy directly from the new_mem buffer

      memcpy(afl->fsrv.shmem_fuzz, new_mem, new_size);

    } else {

      memcpy(afl->fsrv.shmem_fuzz, mem, skip_at);

      memcpy(afl->fsrv.shmem_fuzz + skip_at, mem + skip_at + skip_len,
             tail_len);

    }

    *afl->fsrv.shmem_fuzz_len = new_size;

#ifdef _DEBUG
    if (afl->debug) {

      fprintf(
          stderr, "FS crc: %16llx len: %u\n",
          hash64(afl->fsrv.shmem_fuzz, *afl->fsrv.shmem_fuzz_len, HASH_CONST),
          *afl->fsrv.shmem_fuzz_len);
      fprintf(stderr, "SHM :");
      for (u32 i = 0; i < *afl->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", afl->fsrv.shmem_fuzz[i]);
      fprintf(stderr, "\nORIG:");
      for (u32 i = 0; i < *afl->fsrv.shmem_fuzz_len; i++)
        fprintf(stderr, "%02x", (u8)((u8 *)mem)[i]);
      fprintf(stderr, "\n");

    }

#endif

    return;

  } else if (unlikely(!afl->fsrv.use_stdin)) {

    if (unlikely(afl->no_unlink)) {

      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC,
                DEFAULT_PERMISSION);

    } else {

      unlink(afl->fsrv.out_file);                         /* Ignore errors. */
      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_EXCL,
                DEFAULT_PERMISSION);

    }

    if (fd < 0) { PFATAL("Unable to create '%s'", afl->fsrv.out_file); }

  } else {

    lseek(fd, 0, SEEK_SET);

  }

  if (!post_process_skipped) {

    ck_write(fd, new_mem, new_size, afl->fsrv.out_file);

  } else {

    ck_write(fd, mem, skip_at, afl->fsrv.out_file);

    ck_write(fd, mem + skip_at + skip_len, tail_len, afl->fsrv.out_file);

  }

  if (afl->fsrv.use_stdin) {

    if (ftruncate(fd, new_size)) { PFATAL("ftruncate() failed"); }
    lseek(fd, 0, SEEK_SET);

  } else {

    close(fd);

  }

}

/**
 * @brief Updates a state's score (double) and restores the max-heap property.
 * Uses the hash map for efficient index lookup. Assumes total_score is double.
 *
 * @param afl Pointer to the main AFL state structure.
 * @param state_id The ID of the state to update.
 * @param new_score The new double total score for the state.
 */
void update_state_heap(afl_state_t *afl, u32 state_id, double old_score) { // Changed parameter to double

    u32 index;

    //FILE *score_rec = fopen("score_records","a");
    // Use map lookup to find the correct index
    if (!state_map_lookup(&afl->fsrv, state_id, &index)) {
      //fprintf(score_rec,"not found state id: %d\n", state_id);
        WARNF("State %u not found in state map during heap update!", state_id);
        return;
    }
    // fprintf(score_rec,"found state id: %d\n", state_id);

    //close(score_rec);

    // Get the old score (as double) before updating, using the correct index.
    //double old_score = afl->fsrv.state_info[index].total_score;
    double new_score = afl->fsrv.state_info[index].total_score  ;

    //fprintf(score_rec,"found state index: %d with old score:%.10f, new score %.10f\n", index, old_score, new_score);
    // Update the score (as double) at the correct index.


    // Handle heap update based on score change, using the correct index.
    if (new_score > old_score) {
        // Score increased: Bubble up from the correct index.
        u32 current_index = index;
        //fprintf(score_rec,"current index: %d\n", current_index);
        while (current_index != 0) {
             u32 parent_index = (current_index - 1) / 2;
             // Compare double scores
            //fprintf(score_rec,"current index: %d, score: %.10f , parent index:%d, score:%.10f\n", 
            // current_index, afl->fsrv.state_info[current_index].total_score,
            // parent_index,afl->fsrv.state_info[parent_index].total_score);
             if (afl->fsrv.state_info[parent_index].total_score < afl->fsrv.state_info[current_index].total_score) {
                 // Use the corrected swap function which updates the map
                //  fprintf(score_rec,"swapping\n");
                //  fclose(score_rec);
                
                 swap_state_info(&afl->fsrv, current_index, parent_index);
                 current_index = parent_index; // Continue from the new position
             } else {
                 break; // Heap property satisfied upwards
             }
        }
        //score_rec = fopen("score_records","a");

        u32 ind;
        state_map_lookup(&afl->fsrv, state_id, &ind);
        // fprintf(score_rec,"index was modified to: %d, score: %.10f\n", ind, afl->fsrv.state_info[ind].total_score);
        // fprintf(score_rec,"score at index 0 is: %.10f\n", afl->fsrv.state_info[0].total_score);
        //fclose(score_rec);
    } else if (new_score <= old_score) {
      // score_rec = fopen("score_records","a");
      // fprintf(score_rec,"score decreased, new_score: %.10f, old_score: %.10f\n", new_score, old_score);
      // fclose(score_rec);
        // Score decreased: Call max_heapify (which uses corrected swap)
        state_max_heapify(&afl->fsrv, index);
    } // else score unchanged, no action required.

   // fclose(score_rec);
}

/*
  update the score after the target program is run with current seed
// */
// u8 update_state_scores(afl_state_t *afl) {

//     if (!afl || !afl->fsrv.transition_logs || !afl->queue_top) {
//         WARNF("Missing data for update_state_scores");
//         return 0;
//     }

//     u8 *temp = (u8 *)ck_alloc(MAP_SIZE);
//     if (!temp) {
//          PFATAL("Failed to allocate temp map for score update");
//     }

//     u32 total_unique_depth = 0;
//     u32 trans_count = afl->fsrv.transition_logs->count;

//     //printf("%d\n",trans_count);
//     // --- First Pass: Calculate unique depth ---
//     //FILE *sb1 = fopen("sbsbsb","a");
//     for (u32 i = 0; i < trans_count; ++i) {
//         u32 state_index = afl->fsrv.transition_logs->indexes[i];
//         if (state_index >= MAP_SIZE) continue;
//         if (temp[state_index] == 0) {
//             temp[state_index] = 1;
//             total_unique_depth++;
//         }
//     }

//     // --- Second Pass: Update scores and seed heaps ---
//     memset(temp, 0, MAP_SIZE * sizeof(u8)); // Reset temp map
//     u32 cur_depth = 0; // Use u32 consistently
//     //FILE *score_rec = fopen("score_records","a");
//     double execution_score_base = afl->queue_top->execution_score;
//     //fprintf(score_rec,"%lf\n", execution_score_base);
//     double score_contribution;
//     double new_score;
//     double old_score; // Score before adding delta
//     double epsilon = 1e-9;     // Small epsilon for floating point

//     // Define clamping values as doubles
//     const double MAX_SCORE_FP = 1.0e+10; // Example limits
//     const double MIN_SCORE_FP = -1.0e+10;

//     u32 heap_idx; // Index within the state_info heap array
//     // FILE *score_rec = fopen("score_records","a");
//     // fprintf(score_rec,"update failed, index error\n");
//     // fclose(score_rec);
//     for (u32 i = 0; i < trans_count; ++i) {
//         u32 state_index = afl->fsrv.transition_logs->indexes[i];
//         // score_rec = fopen("score_records","a");
//         // fprintf(score_rec,"go die: %d, trans_count: %d\n", state_index, i);
//         // fclose(score_rec);
//         if (state_index >= MAP_SIZE) { 
//           continue;
//           };

//         // Process each *unique* state only once for score calculation
//         if (temp[state_index] == 0) {
//             temp[state_index] = 1; // Mark as processed

//             if (!state_map_lookup(&afl->fsrv, state_index, &heap_idx)) {
//               // score_rec = fopen("score_records","a");
//               // fprintf(score_rec,"go die122223: %d\n", state_index);
//               // fclose(score_rec);

//               continue;
//             }

//             state_info_t *cur_state_ptr = &afl->fsrv.state_info[heap_idx];

//             // --- Calculate Score Delta using Floating-Point ---
//             u32 shift_amount = (total_unique_depth > cur_depth) ? (total_unique_depth - cur_depth) : 0;
//             shift_amount = MIN(shift_amount, (u32)63); // Prevent excessive shift for divisor

//             // Calculate divisor (2^shift_amount)
//             double divisor = (double)(1ULL << shift_amount);

//             // *** MODIFIED LINE: Use floating-point division ***

//             score_contribution = (divisor > 0.0) ? ((double)execution_score_base / divisor) : (double)execution_score_base;

//             // Ensure minimum score using floating-point epsilon
//             score_contribution = MAX(epsilon, score_contribution);
//             //fprintf(score_rec,"go die: %d, score base:%.12f, shift:%d, score distribution: %.12f\n", state_index, execution_score_base, shift_amount, score_contribution);
//             // Calculate new score (double + double, assuming cur_state_ptr->total_score is double)
//             old_score = cur_state_ptr->total_score; // Read current double score
//             new_score = old_score + score_contribution;
//             //fprintf(score_rec,"go die: %d, new score: %10f\n", state_index, new_score);

//             if (new_score > 0.0){
//               //fprintf(score_rec,"new scores: %f\n",new_score);
//               }


//             // Clamp the score (using double limits)
//             // new_score = MAX(MIN_SCORE_FP, MIN(new_score, MAX_SCORE_FP));
//             // printf("new scores: %f\n", new_score);
//             // --- Update State Score and Heap ---
//             // Use atomic store if available for doubles, otherwise standard assignment
//             // NOTE: Standard C atomics don't directly support double, might need compiler intrinsics
//             // or rely on single-threaded access for this update.
            
//             cur_state_ptr->total_score = new_score; // Assuming single-threaded update context
//             // score_rec = fopen("score_records","a");
//             // fprintf(score_rec," updating the index: %d, with score %.10f\n", state_index, new_score);
//             // fclose(score_rec);
//             // Update the state heap (must be modified to handle double scores)
//             update_state_heap(afl, state_index, old_score); // Pass double score
            
//             // --- Update Seed Heap (Operating on the POINTER) ---
//             u8 res = update_seed_hits(cur_state_ptr, afl->queue_top->id);
//             if (!res) {
//                 insert_seed(cur_state_ptr, afl->queue_top->id, 1);
//             }

//             cur_depth++; // Increment depth only for unique states processed
//         }
//     } 
//     ck_free(temp);
//     return 1;
// }
#ifndef MIN_STATE_SCORE_FP
  // Define the minimum allowed score for a state.
  // This prevents scores from becoming excessively negative.
  #define MIN_STATE_SCORE_FP -1.0e+12
#endif

#ifndef MAX_STATE_SCORE_FP
  // Define the maximum allowed score for a state.
  // This prevents scores from becoming excessively large.
  #define MAX_STATE_SCORE_FP 1.0e+12
#endif

#ifndef DEFAULT_NEW_SEED_SCORE_IN_STATE_HEAP
  #define DEFAULT_NEW_SEED_SCORE_IN_STATE_HEAP 5.0
#endif


u8 update_state_scores(afl_state_t *afl, u8 new_seed_was_saved_this_iteration) {

    // --- Pre-computation Checks ---
    if (!afl || !afl->fsrv.transition_logs || !afl->fsrv.state_info) {
        WARNF("Missing data structures for update_state_scores (logs, state_info, or state_map).");
        return 0;
    }

    // Get the original seed that was mutated for this run.
    // afl->queue_cur should point to this original seed.
    struct queue_entry *original_seed_entry = afl->queue_cur;
    if (!original_seed_entry) {
        WARNF("afl->queue_cur is NULL in update_state_scores. Cannot attribute original seed score.");
        // If we can't identify the original seed, we might still update state scores
        // but skip seed heap updates for the original seed.
    }
    u32 original_seed_id = original_seed_entry ? original_seed_entry->id : 0xFFFFFFFF; // Invalid ID if no current original seed

    // Get the number of transitions recorded in this run
    u32 trans_count = afl->fsrv.transition_logs->count;
    if (trans_count == 0) {

        return 1; // Not a failure, just nothing to do
    }

    // Get the base score for the last execution, set by common_fuzz_stuff
    double execution_score_base = afl->current_execution_score_base;

    // --- First Pass: Calculate Unique Depth and Identify Unique States ---
    // Use calloc for zero-initialization. Use afl->fsrv.map_size for correct bounds.
    u32 ss = afl->fsrv.map_size * sizeof(u8);
    u8 *unique_state_tracker = ck_alloc(ss);
    // ck_calloc PFATALs on failure, no need to check for NULL here.

    u32 total_unique_depth = 0;
    for (u32 i = 0; i < trans_count; ++i) {
        u32 state_index = afl->fsrv.transition_logs->indexes[i];
        if (state_index >= afl->fsrv.map_size) { // Use actual map size
             WARNF("Invalid state_index %u in transition log (map_size %u)", state_index, afl->fsrv.map_size);
             continue;
        }
        if (unique_state_tracker[state_index] == 0) {
            unique_state_tracker[state_index] = 1; // Mark as seen
            total_unique_depth++;
        }
    }

    if (total_unique_depth == 0) {
        ck_free(unique_state_tracker);
        return 1; // No valid unique states found
    }

    // --- Second Pass: Update Scores for Unique States ---
    memset(unique_state_tracker, 0, afl->fsrv.map_size * sizeof(u8)); // Reset tracker
    u32 cur_unique_depth_index = 0; // 0-indexed count of unique states processed in this trace

    double epsilon = 1e-9; // Small epsilon for floating point comparisons

    for (u32 i = 0; i < trans_count; ++i) {
        u32 state_index = afl->fsrv.transition_logs->indexes[i];
        if (state_index >= afl->fsrv.map_size) {
            continue;
        }

        // Process each *unique* state only once for score calculation
        if (unique_state_tracker[state_index] == 0) {
            unique_state_tracker[state_index] = 1; // Mark as processed for this pass

            u32 heap_idx; // Index within the main state_info heap array

            // State Lookup - Assuming all states are pre-initialized.
            if (!state_map_lookup(&afl->fsrv, state_index, &heap_idx)) {
                // This should not happen if all states are pre-initialized as per user's previous comment.
                WARNF("State %u not found in state_map during update_state_scores. This indicates an issue with state initialization.", state_index);
                continue; // Skip this problematic state.
            }
            
            // State exists, increment its hit_count
            afl->fsrv.state_info[heap_idx].hit_count++;


            state_info_t *cur_state_ptr = &afl->fsrv.state_info[heap_idx];
            double old_total_score = cur_state_ptr->total_score;

            // --- Calculate Score Contribution for this State ---
            // Proximity weighting: states later in the unique trace get a larger portion of the score.
            u32 proximity_rank = total_unique_depth - 1 - cur_unique_depth_index;
            u32 shift_amount = MIN(proximity_rank, (u32)63); 

            double divisor = (double)(1ULL << shift_amount);
            double score_contribution;

            if (fabs(divisor) < epsilon) { // Avoid division by zero or very small numbers
                score_contribution = execution_score_base;
            } else {
                score_contribution = execution_score_base / divisor;
            }
            
            // If execution_score_base was positive, ensure score_contribution is also positive (or at least non-negative).
            if (execution_score_base > 0 && score_contribution < 0) { // Check if it flipped sign
                score_contribution = epsilon; 
            }


            // --- Update State's Total Score ---
            double new_total_score = old_total_score + score_contribution;
            new_total_score = MAX(MIN_STATE_SCORE_FP, MIN(new_total_score, MAX_STATE_SCORE_FP));
            cur_state_ptr->total_score = new_total_score;
            update_state_heap(afl, state_index, old_total_score);

            // --- Update Seed Heap for the ORIGINAL SEED ---
            // Only update if the original seed ID is valid and the overall execution
            // had a positive outcome (meriting reinforcement for the seed in this state).
            if (original_seed_id != 0xFFFFFFFF && execution_score_base > 0) {
                // The score_contribution for the state can be used as the basis for
                // the seed's score increment within this state's local seed heap.
                double seed_boost_for_original = score_contribution; 
                upsert_seed_in_state_heap((seed_heap_for_state_t*)&(cur_state_ptr->top_seeds),
                                           original_seed_id,
                                           seed_boost_for_original);
                cur_state_ptr->top_seeds_full = (cur_state_ptr->heap_size == MAX_TOP_SEEDS);
            }

            // --- Update Seed Heap for the NEWLY SAVED SEED (if any) ---
            // This block executes if a new seed was saved in the *current* iteration of common_fuzz_stuff
            // AND that new seed is different from the original seed being fuzzed (or original seed was invalid).
            if (new_seed_was_saved_this_iteration && afl->queue_top && 
                (original_seed_id == 0xFFFFFFFF || afl->queue_top->id != original_seed_id)) {
                
                u32 newly_saved_seed_id = afl->queue_top->id;
                double seed_boost_for_new_saved_seed;

                // If the overall execution that LED to this new seed was positive,
                // use its score contribution. Otherwise, give a default positive score.
                if (execution_score_base > 0) {
                    // Using the same score_contribution as the original seed got for this state
                    // implies that this new seed is also valuable for reaching this state
                    // and contributing to this positive outcome.
                    seed_boost_for_new_saved_seed = score_contribution;
                } else {
                    // This case is less likely if a new seed was saved (saving usually implies positive outcome),
                    // but as a fallback, give it a default positive score for being a new, interesting input
                    // that reaches this state.
                    seed_boost_for_new_saved_seed = DEFAULT_NEW_SEED_SCORE_IN_STATE_HEAP;
                }
                
                // Only add/update if the boost is positive.
                if (seed_boost_for_new_saved_seed > 0) {
                    upsert_seed_in_state_heap((seed_heap_for_state_t*)&(cur_state_ptr->top_seeds),
                                               newly_saved_seed_id,
                                               seed_boost_for_new_saved_seed);
                    // The top_seeds_full flag would be updated based on heap_size after upsert.
                    // This depends on how upsert_seed_in_state_heap modifies cur_state_ptr->heap_size.
                    // For now, we assume it's managed correctly by upsert or needs re-evaluation here.
                    cur_state_ptr->top_seeds_full = (cur_state_ptr->heap_size == MAX_TOP_SEEDS);
                }
            }
            cur_unique_depth_index++; // Increment for the next unique state
        }
    }
    ck_free(unique_state_tracker);
    return 1;
}

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  u8 fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
     first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us, diff_us;
  s32 old_sc = afl->stage_cur, old_sm = afl->stage_max;
  u32 use_tmout = afl->fsrv.exec_tmout;
  u8 *old_sn = afl->stage_name;

  u64 calibration_start_us = get_cur_time_us();
  if (unlikely(afl->shm.cmplog_mode)) { q->exec_cksum = 0; }

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || afl->resuming_fuzz) {

    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  }

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->afl_env.afl_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!afl->fsrv.fsrv_pid) {

    if (afl->fsrv.cmplog_binary &&
        afl->fsrv.init_child_func != cmplog_exec_child) {

      FATAL("BUG in afl-fuzz detected. Cmplog mode not set correctly.");

    }

    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child);

    if (afl->fsrv.support_shmem_fuzz && !afl->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(afl->shm_fuzz);
      ck_free(afl->shm_fuzz);
      afl->shm_fuzz = NULL;
      afl->fsrv.support_shmem_fuzz = 0;
      afl->fsrv.shmem_fuzz = NULL;

    }

  }

  u8 saved_afl_post_process_keep_original =
      afl->afl_env.afl_post_process_keep_original;
  afl->afl_env.afl_post_process_keep_original = 1;

  /* we need a dummy run if this is LTO + cmplog */
  if (unlikely(afl->shm.cmplog_mode)) {

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) q->bitsmap_size = afl->bitsmap_size;
#endif

  }

  if (q->exec_cksum) {

    memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);
    hnb = has_new_bits(afl, afl->virgin_bits);
    if (hnb > new_bits) { new_bits = hnb; }

  }

  start_us = get_cur_time_us();

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    if (unlikely(afl->debug)) {

      DEBUGF("calibration stage %d/%d\n", afl->stage_cur + 1, afl->stage_max);

    }

    u64 cksum;

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = fuzz_run_target(afl, &afl->fsrv, use_tmout);

    // update the time spend in calibration after each execution, as those may
    // be slow
    update_calibration_time(afl, &calibration_start_us);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) q->bitsmap_size = afl->bitsmap_size;
#endif

    classify_counts(&afl->fsrv);
    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    if (q->exec_cksum != cksum) {

      hnb = has_new_bits(afl, afl->virgin_bits);
      if (hnb > new_bits) { new_bits = hnb; }

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < afl->fsrv.map_size; ++i) {

          if (unlikely(!afl->var_bytes[i]) &&
              unlikely(afl->first_trace[i] != afl->fsrv.trace_bits[i])) {

            afl->var_bytes[i] = 1;
            // ignore the variable edge by setting it to fully discovered
            afl->virgin_bits[i] = 0;

          }

        }

        if (unlikely(!var_detected && !afl->afl_env.afl_no_warn_instability)) {

          // note: from_queue seems to only be set during initialization
          if (afl->afl_env.afl_no_ui || from_queue) {

            WARNF("instability detected during calibration");

          } else if (afl->debug) {

            DEBUGF("instability detected during calibration\n");

          }

        }

        var_detected = 1;
        afl->stage_max =
            afl->afl_env.afl_cal_fast ? CAL_CYCLES : CAL_CYCLES_LONG;

      } else {

        q->exec_cksum = cksum;
        memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

      }

    }

  }

  if (unlikely(afl->fixed_seed)) {

    diff_us = (u64)(afl->fsrv.exec_tmout - 1) * (u64)afl->stage_max;

  } else {

    stop_us = get_cur_time_us();
    diff_us = stop_us - start_us;
    if (unlikely(!diff_us)) { ++diff_us; }

  }

  afl->total_cal_us += diff_us;
  afl->total_cal_cycles += afl->stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  if (unlikely(!afl->stage_max)) {

    // Pretty sure this cannot happen, yet scan-build complains.
    FATAL("BUG: stage_max should not be 0 here! Please report this condition.");

  }

  q->exec_us = diff_us / afl->stage_max;
  if (unlikely(!q->exec_us)) { q->exec_us = 1; }

  q->bitmap_size = count_bytes(afl, afl->fsrv.trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  afl->total_bitmap_size += q->bitmap_size;
  ++afl->total_bitmap_entries;

  update_bitmap_score(afl, q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!afl->non_instrumented_mode && first_run && !fault && !new_bits) {

    fault = FSRV_RUN_NOBITS;

  }

abort_calibration:

  afl->afl_env.afl_post_process_keep_original =
      saved_afl_post_process_keep_original;

  if (new_bits == 2 && !q->has_new_cov) {

    q->has_new_cov = 1;
    ++afl->queued_with_cov;

  }

  /* Mark variable paths. */

  if (var_detected) {

    afl->var_byte_count = count_bytes(afl, afl->var_bytes);

    if (!q->var_behavior) {

      mark_as_variable(afl, q);
      ++afl->queued_variable;

    }

  }

  afl->stage_name = old_sn;
  afl->stage_cur = old_sc;
  afl->stage_max = old_sm;

  if (!first_run) { show_stats(afl); }

  update_calibration_time(afl, &calibration_start_us);
  return fault;

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(afl_state_t *afl) {

  if (unlikely(afl->afl_env.afl_no_sync)) { return; }

  DIR           *sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0, synced = 0, entries = 0;
  u8             path[PATH_MAX + 1 + NAME_MAX];

  sd = opendir(afl->sync_dir);
  if (!sd) { PFATAL("Unable to open '%s'", afl->sync_dir); }

  afl->stage_max = afl->stage_cur = 0;
  afl->cur_depth = 0;

  u64 sync_start_us = get_cur_time_us();
  /* Look at the entries created for every other fuzzer in the sync directory.
   */

  while ((sd_ent = readdir(sd))) {

    // since sync can take substantial amounts of time, update time spend every
    // iteration
    update_sync_time(afl, &sync_start_us);

    u8  qd_synced_path[PATH_MAX], qd_path[PATH_MAX];
    u32 min_accept = 0, next_min_accept = 0;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(afl->sync_id, sd_ent->d_name)) {

      continue;

    }

    entries++;

    // secondary nodes only syncs from main, the main node syncs from everyone
    if (likely(afl->is_secondary_node)) {

      sprintf(qd_path, "%s/%s/is_main_node", afl->sync_dir, sd_ent->d_name);
      int res = access(qd_path, F_OK);
      if (unlikely(afl->is_main_node)) {  // an elected temporary main node

        if (likely(res == 0)) {  // there is another main node? downgrade.

          afl->is_main_node = 0;
          sprintf(qd_path, "%s/is_main_node", afl->out_dir);
          unlink(qd_path);

        }

      } else {

        if (likely(res != 0)) { continue; }

      }

    }

    synced++;

    /* document the attempt to sync to this instance */

    sprintf(qd_synced_path, "%s/.synced/%s.last", afl->out_dir, sd_ent->d_name);
    id_fd =
        open(qd_synced_path, O_RDWR | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);
    if (id_fd >= 0) close(id_fd);

    /* Skip anything that doesn't have a queue/ subdirectory. */

    sprintf(qd_path, "%s/%s/queue", afl->sync_dir, sd_ent->d_name);

    struct dirent **namelist = NULL;
    int             m = 0, n, o;

    n = scandir(qd_path, &namelist, NULL, alphasort);

    if (n < 1) {

      if (namelist) free(namelist);
      continue;

    }

    /* Retrieve the ID of the last seen test case. */

    sprintf(qd_synced_path, "%s/.synced/%s", afl->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, DEFAULT_PERMISSION);

    if (id_fd < 0) { PFATAL("Unable to create '%s'", qd_synced_path); }

    if (read(id_fd, &min_accept, sizeof(u32)) == sizeof(u32)) {

      next_min_accept = min_accept;
      lseek(id_fd, 0, SEEK_SET);

    }

    /* Show stats */

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "sync %u", ++sync_cnt);

    afl->stage_name = afl->stage_name_buf;
    afl->stage_cur = 0;
    afl->stage_max = 0;

    show_stats(afl);

    /* For every file queued by this fuzzer, parse ID and see if we have
       looked at it before; exec a test case if not. */

    u8 entry[12];
    sprintf(entry, "id:%06u", next_min_accept);

    while (m < n) {

      if (strncmp(namelist[m]->d_name, entry, 9)) {

        m++;

      } else {

        break;

      }

    }

    if (m >= n) { goto close_sync; }  // nothing new

    for (o = m; o < n; o++) {

      s32         fd;
      struct stat st;

      snprintf(path, sizeof(path), "%s/%s", qd_path, namelist[o]->d_name);
      afl->syncing_case = next_min_accept;
      next_min_accept++;

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) { continue; }

      if (fstat(fd, &st)) { WARNF("fstat() failed"); }

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) { PFATAL("Unable to mmap '%s'", path); }

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        u32 new_len = write_to_testcase(afl, (void **)&mem, st.st_size, 1);

        fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

        if (afl->stop_soon) { goto close_sync; }

        afl->syncing_party = sd_ent->d_name;
        afl->queued_imported += save_if_interesting(afl, mem, new_len, fault);
        show_stats(afl);
        afl->syncing_party = 0;

        munmap(mem, st.st_size);

      }

      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

  close_sync:
    close(id_fd);
    if (n > 0)
      for (m = 0; m < n; m++)
        free(namelist[m]);
    free(namelist);

  }

  closedir(sd);

  // If we are a secondary and no main was found to sync then become the main
  if (unlikely(synced == 0) && likely(entries) &&
      likely(afl->is_secondary_node)) {

    // there is a small race condition here that another secondary runs at the
    // same time. If so, the first temporary main node running again will demote
    // themselves so this is not an issue

    //    u8 path2[PATH_MAX];
    afl->is_main_node = 1;
    sprintf(path, "%s/is_main_node", afl->out_dir);
    int fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd >= 0) { close(fd); }

  }

  if (afl->foreign_sync_cnt) read_foreign_testcases(afl, 0);

  // add time in sync one last time
  update_sync_time(afl, &sync_start_us);

  afl->last_sync_time = get_cur_time();
  afl->last_sync_cycle = afl->queue_cycle;

}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {

  u8  needs_write = 0, fault = 0;
  u32 orig_len = q->len;
  u64 trim_start_us = get_cur_time_us();
  /* Custom mutator trimmer */
  if (afl->custom_mutators_count) {

    u8   trimmed_case = 0;
    bool custom_trimmed = false;

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_trim) {

        trimmed_case = trim_case_custom(afl, q, in_buf, el);
        custom_trimmed = true;

      }

    });

    if (orig_len != q->len || custom_trimmed) {

      queue_testcase_retake(afl, q, orig_len);

    }

    if (custom_trimmed) {

      fault = trimmed_case;
      goto abort_trimming;

    }

  }

  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (unlikely(q->len < 5)) {

    fault = 0;
    goto abort_trimming;

  }

  afl->stage_name = afl->stage_name_buf;
  afl->bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_pow2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, (u32)TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, (u32)TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(afl->stage_name_buf, "trim %s/%s",
            u_stringify_int(val_bufs[0], remove_len),
            u_stringify_int(val_bufs[1], remove_len));

    afl->stage_cur = 0;
    afl->stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u64 cksum;

      write_with_gap(afl, in_buf, q->len, remove_pos, trim_avail);

      fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

      update_trim_time(afl, &trim_start_us);

      if (afl->stop_soon || fault == FSRV_RUN_ERROR) { goto abort_trimming; }

      /* Note that we don't keep track of crashes or hangs here; maybe TODO?
       */

      ++afl->trim_execs;
      classify_counts(&afl->fsrv);
      cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2 = next_pow2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */
        if (!needs_write) {

          needs_write = 1;
          memcpy(afl->clean_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

        }

      } else {

        remove_pos += remove_len;

      }

      /* Since this can be slow, update the screen every now and then. */
      if (!(trim_exec++ % afl->stats_update_freq)) { show_stats(afl); }
      ++afl->stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    // run afl_custom_post_process

    if (unlikely(afl->custom_mutators_count) &&
        likely(!afl->afl_env.afl_post_process_keep_original)) {

      ssize_t new_size = q->len;
      u8     *new_mem = in_buf;
      u8     *new_buf = NULL;

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (el->afl_custom_post_process) {

          new_size = el->afl_custom_post_process(el->data, new_mem, new_size,
                                                 &new_buf);

          if (unlikely(!new_buf || new_size <= 0)) {

            new_size = 0;
            new_buf = new_mem;

          } else {

            new_mem = new_buf;

          }

        }

      });

      if (unlikely(!new_size)) {

        new_size = q->len;
        new_mem = in_buf;

      }

      if (unlikely(new_size < afl->min_length)) {

        new_size = afl->min_length;

      } else if (unlikely(new_size > afl->max_length)) {

        new_size = afl->max_length;

      }

      q->len = new_size;

      if (new_mem != in_buf && new_mem != NULL) {

        new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), new_size);
        if (unlikely(!new_buf)) { PFATAL("alloc"); }
        memcpy(new_buf, new_mem, new_size);

        in_buf = new_buf;

      }

    }

    s32 fd;

    if (unlikely(afl->no_unlink)) {

      fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      u32 written = 0;
      while (written < q->len) {

        ssize_t result = write(fd, in_buf, q->len - written);
        if (result > 0) written += result;

      }

    } else {

      unlink(q->fname);                                    /* ignore errors */
      fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

      if (fd < 0) { PFATAL("Unable to create '%s'", q->fname); }

      ck_write(fd, in_buf, q->len, q->fname);

    }

    close(fd);

    queue_testcase_retake_mem(afl, q, in_buf, q->len, orig_len);

    memcpy(afl->fsrv.trace_bits, afl->clean_trace, afl->fsrv.map_size);
    update_bitmap_score(afl, q);

  }

abort_trimming:
  afl->bytes_trim_out += q->len;
  update_trim_time(afl, &trim_start_us);

  return fault;

}


#ifndef SCORE_CRASH
#define SCORE_CRASH                 1000.0 // 发现崩溃时的分数
#endif
#ifndef SCORE_NEW_HANG
#define SCORE_NEW_HANG              50.0   // 发现新的独特挂起/超时时的分数
#endif
#ifndef SCORE_KNOWN_HANG_OR_TMOUT
#define SCORE_KNOWN_HANG_OR_TMOUT   1.0    // 重复的超时/挂起时的分数 (可以很低或为负)
#endif
#ifndef SCORE_NEW_PATH
#define SCORE_NEW_PATH              20.0   // 发现添加到队列的新路径时的分数
#endif
#ifndef SCORE_NEW_BITS_GENERIC
#define SCORE_NEW_BITS_GENERIC      5.0    // 发现新的位图边（但不足以加入队列）时的分数
#endif
#ifndef SCORE_DECAY
#define SCORE_DECAY                 -0.5   // 如果没有发生有趣的事情，则应用负分（用于状态分数衰减）
#endif





/*
 * 概念性函数，用于检查独特的挂起。
 * 如果需要，请替换为您的实际实现。
 */
// static u8 is_new_unique_hang(afl_state_t *afl, u8 *trace_bits) {
//   // 检查当前 trace_bits (简化后) 是否对应于新的挂起签名
//   // 基于 afl->virgin_tmout 或自定义挂起跟踪机制。
//   if (!afl->non_instrumented_mode) {
//      // 如果尚未完成，可能需要 simplify_trace
//      return has_new_bits(afl, afl->virgin_tmout);
//   }
//   return 1; // 如果未插桩或无跟踪，则假设为新
// }


#include "afl-fuzz.h"           // Main AFL++ header
#include "afl-state-seed-heap.h" // Include header for seed heap functions if separate

#ifndef SCORE_CRASH
#define SCORE_CRASH                 1000.0 // Score for finding a crash
#endif
#ifndef SCORE_NEW_HANG
#define SCORE_NEW_HANG              50.0   // Score for finding a new unique hang/timeout
#endif
#ifndef SCORE_KNOWN_HANG_OR_TMOUT
#define SCORE_KNOWN_HANG_OR_TMOUT   1.0    // Score for a repeated timeout/hang (can be low or negative)
#endif
#ifndef SCORE_NEW_PATH
#define SCORE_NEW_PATH              20.0   // Score for finding a new path added to the queue
#endif
#ifndef SCORE_NEW_BITS_GENERIC
#define SCORE_NEW_BITS_GENERIC      5.0    // Score for finding new bitmap edges (not queue-worthy)
#endif
#ifndef SCORE_DECAY
#define SCORE_DECAY                 -0.5   // Score applied if nothing interesting happened (for state score decay)
#endif
// DEFAULT_NEW_SEED_SCORE_IN_STATE_HEAP is used in update_state_scores, ensure it's defined.

/**
 * @brief Executes the target with the given input, analyzes the outcome,
 * calculates an execution score, and updates state scores accordingly.
 * Handles timeouts and skip requests.
 * @param afl Pointer to the main AFL++ state.
 * @param out_buf Buffer containing the input for the target.
 * @param len Length of the input buffer.
 * @return 0 if fuzzing should continue for the current queue entry,
 * 1 if it's time to abandon the current entry (stop_soon, skip, timeout limit).
 */
u8 __attribute__((hot)) common_fuzz_stuff(afl_state_t *afl, u8 *out_buf,
                                          u32 len) {

  u8 fault; // Stores the execution result from the target

  // Capture the current seed being fuzzed, as afl->queue_cur might change
  // if save_if_interesting triggers calibration.
  struct queue_entry * current_seed_being_fuzzed = afl->queue_cur;
  if (!current_seed_being_fuzzed) {
      WARNF("afl->queue_cur is NULL in common_fuzz_stuff!");
      // This is a critical issue, likely indicates a bug elsewhere or an unexpected state.
      // Returning 1 to abandon the current fuzz_one cycle might be safest.
      return 1;
  }


  // --- 1. Prepare and Run Target ---

  // Write the potentially mutated input to the target's input file or shared memory.
  // write_to_testcase might return 0 if a post-processor fails or input length becomes 0.
  if (unlikely(len = write_to_testcase(afl, (void **)&out_buf, len, 0)) == 0) {
    // If input preparation failed or resulted in zero length, skip this specific mutation.
    // Don't abandon the whole queue entry yet, just this mutation.
    return 0;
  }

  // Clear the transition log shared memory before the child process runs.
  // This ensures the log only contains transitions from the upcoming execution.
  if (likely(afl->shm.trans_log_map)) {
      // Assuming trans_log_t has 'count' and 'indexes' members
      memset(afl->shm.trans_log_map, 0, sizeof(trans_log_t));
  } else {
      // This should ideally not happen if initialization was successful.
      WARNF("Transition log shared memory map not available in common_fuzz_stuff!");
      // Consider if this is fatal or if state scoring should be skipped for this run.
      // If it's critical, you might return 1 or PFATAL. For now, we'll proceed but state scoring will be impacted.
  }
  
  // Update prev_saved_hangs *before* the run that might discover a new hang.
  // This allows us to detect if save_if_interesting actually saved a new hang in this iteration.
  afl->prev_saved_hangs = afl->saved_hangs;

  // Execute the target application with the prepared input.
  fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);


  // --- 2. Handle Immediate Exit/Skip Conditions ---

  // Check if Ctrl+C was pressed.
  if (afl->stop_soon) { return 1; }

  // Handle timeouts: Increment consecutive timeout counter. If limit reached,
  // skip the rest of the mutations for this seed.
  if (fault == FSRV_RUN_TMOUT) {
    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {
      WARNF("Input from '%s' caused %d consecutive timeouts, abandoning this queue entry.",
            current_seed_being_fuzzed->fname, TMOUT_LIMIT);
      ++afl->cur_skipped_items;
      // Assign a penalty score before abandoning the entry.
      afl->current_execution_score_base = SCORE_DECAY * 10.0; // Example heavy penalty
      if (likely(afl->fsrv.transition_logs) && afl->shm.trans_log_map) { // Check if logs are available before updating
           update_state_scores(afl, 0); // Pass 0 for new_seed_was_saved
      }
      return 1; // Abandon this queue entry for this fuzz_one cycle.
    }
  } else {
    afl->subseq_tmouts = 0; // Reset counter if the run wasn't a timeout.
  }

  // Handle external skip request (SIGUSR1).
  if (afl->skip_requested) {
    afl->skip_requested = 0;
    ++afl->cur_skipped_items;
    // Assign decay score before skipping.
    afl->current_execution_score_base = SCORE_DECAY;
     if (likely(afl->fsrv.transition_logs) && afl->shm.trans_log_map) {
        update_state_scores(afl, 0); // Pass 0 for new_seed_was_saved
     }
    return 1; // Abandon this queue entry for this fuzz_one cycle.
  }


  // --- 3. Analyze Execution Results & Save Interesting Cases ---

  // Keep track if save_if_interesting adds a new entry to the main queue.
  u32 sb_queued_discovered = afl->queued_discovered; // Store count before save_if_interesting
  // 'discovered_this_run' will be 1 if save_if_interesting saved a new seed to the main queue, 0 otherwise.
  u32 discovered_this_run = save_if_interesting(afl, out_buf, len, fault); 
  // afl->queued_discovered is updated inside save_if_interesting if a new seed is added.

  afl->queued_discovered += discovered_this_run;
  u8 new_seed_was_saved_this_iteration = (afl->queued_discovered > sb_queued_discovered);


  // Check if *any* new bitmap edges were hit in this run, even if not saved as a new seed.
  // This check should happen *after* save_if_interesting, as it might classify counts and update virgin maps.
  u8 new_bits_overall = has_new_bits(afl, afl->virgin_bits);


  // --- 4. Calculate Execution Score ---

  // Determine the score based *only* on the outcome of this single execution.
  double exec_score_for_this_run = 0.0;

  if (fault == FSRV_RUN_CRASH) {
      // Highest score for finding a crash.
      exec_score_for_this_run = SCORE_CRASH;
  } else if (fault == FSRV_RUN_TMOUT) {
      // Score depends on whether it's a potentially new/unique hang.
      // Using the increase in saved_hangs (updated by save_if_interesting) as a proxy.
      if (afl->saved_hangs > afl->prev_saved_hangs) { 
           exec_score_for_this_run = SCORE_NEW_HANG;
      } else {
           exec_score_for_this_run = SCORE_KNOWN_HANG_OR_TMOUT;
      }
  } else if (new_seed_was_saved_this_iteration) { 
      // Good score if it resulted in a new entry in the main queue.
      exec_score_for_this_run = SCORE_NEW_PATH;
  } else if (new_bits_overall) {
      // Moderate score if new bitmap edges were found, but not enough for the main queue.
      exec_score_for_this_run = SCORE_NEW_BITS_GENERIC;
  } else {
      // Negative score (decay) if no crash, hang, or new coverage was found.
      exec_score_for_this_run = SCORE_DECAY;
  }

  // Store the calculated score in the dedicated field within afl_state_t.
  // update_state_scores will read this value.
  afl->current_execution_score_base = exec_score_for_this_run;


  // --- 5. Update State Scores (Unconditionally for all analyzed runs) ---

  // Update the scores of all states visited in this execution based on the
  // current_execution_score_base. This also updates the internal seed heaps
  // for each visited state, crediting the *original* seed (current_seed_being_fuzzed)
  // and potentially the *newly saved seed*.
  // Only proceed if the transition log structure is valid and was populated.
  if (likely(afl->fsrv.transition_logs) && afl->shm.trans_log_map && afl->shm.trans_log_map->count > 0) {
       update_state_scores(afl, new_seed_was_saved_this_iteration); // Pass the flag
  }


  // --- 6. Update UI Stats ---

  // Refresh the UI periodically or at the end of a stage.
  if (!(afl->stage_cur % afl->stats_update_freq) ||
      (afl->stage_cur + 1 == afl->stage_max)) {
    show_stats(afl);
  }

  // Return 0 to signal that fuzzing for the current queue entry should continue.
  return 0;

} // end common_fuzz_stuff
