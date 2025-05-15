/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include "asanfuzz.h"

u16 count_class_lookup16[65536];

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
static const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

#if __has_builtin(__builtin_popcount)
    ret += __builtin_popcount(v);
#else
    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;
#endif

  }

  return ret;

}

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}

/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  return has_new_bits(afl, virgin_map);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  u8 is_timeout = 0;
  u8 san_crash_only = (afl->san_case_status & SAN_CRASH_ONLY);
  u8 non_cov_incr = (afl->san_case_status & NON_COV_INCREASE_BUG);

  if (new_bits & 0xf0) {

    new_bits -= 0x80;
    is_timeout = 1;

  }

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) {

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu,execs:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time,
            afl->fsrv.total_execs);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov") - 2;
      if (is_timeout) { size_left -= strlen(",+tout"); }
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);

      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);

      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

      }

    }

  }

  if (is_timeout) { strcat(ret, ",+tout"); }

  if (new_bits == 2) { strcat(ret, ",+cov"); }

  if (san_crash_only) { strcat(ret, ",+san"); }

  if (non_cov_incr) { strcat(ret, ",+noncov"); }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}


inline u32 count_class_changes(afl_state_t *afl, u8 *virgin_map) {

  u8  *current = afl->fsrv.trace_bits;
  u8  *virgin = virgin_map;
  u32  new_hit_count = 0;
  u32  i = afl->fsrv.map_size;

  while (i--) {
    u8 cur_val = *(current++);
    u8 vir_val = *(virgin++);

    // If the current value is not zero, and it's different from the virgin map
    if (cur_val && cur_val != vir_val) {
        // Check the lookup table to see the "bucket" of the current count.
        u8 cur_class = count_class_lookup8[cur_val];
        // Check the "bucket" of the virgin map value.
        u8 vir_class = count_class_lookup8[vir_val];

        // If current class is greater, we have new hits.
        if (cur_class > vir_class) {
            // Count the *difference* in hits, not just presence/absence
            new_hit_count += (cur_class - vir_class);
        }
    }
  }
  return new_hit_count;
}

inline u32 count_new_hits(afl_state_t *afl, u8 *virgin_map) {

  u8  *current = afl->fsrv.trace_bits;
  u8  *virgin = virgin_map;
  u32  new_hit_count = 0;
  u32  i = afl->fsrv.map_size;

  while (i--) {
    u8 cur_val = *(current++);
    u8 vir_val = *(virgin++);

    // If the current value is not zero, and it's different from the virgin map
    if (cur_val && cur_val != vir_val) {
        // Check the lookup table to see the "bucket" of the current count.
        u8 cur_class = count_class_lookup8[cur_val];
        // Check the "bucket" of the virgin map value.
        u8 vir_class = count_class_lookup8[vir_val];

        // If current class is greater, we have new hits.
        if (cur_class > vir_class) {
            // Count the *difference* in hits, not just presence/absence
            new_hit_count += (cur_class - vir_class);
        }
    }
  }
  return new_hit_count;
}


#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "post\n"
      "to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the "
      "issues\n"
      " are fixed :)\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

static inline void bitmap_set(u8 *map, u32 index) {

  map[index / 8] |= (1u << (index % 8));

}

static inline u8 bitmap_read(u8 *map, u32 index) {

  return (map[index / 8] >> (index % 8)) & 1;

}

// Ensure these score constants are defined (e.g., in afl-fuzz.h)
#define SCORE_CRASH                 1000.0
#define SCORE_NEW_HANG              50.0
#define SCORE_KNOWN_HANG_OR_TMOUT   1.0
#define SCORE_NEW_PATH_BASE         15.0
#define SCORE_NEW_BITS_GENERIC_BASE 2.0 // Not used directly if new_bits_type > 0 implies new path
#define SCORE_DECAY                 -0.005

#include "afl-fuzz.h" // Ensure this includes definitions for SCORE_CRASH, etc.

// Ensure these score constants are defined (e.g., in afl-fuzz.h)
// #define SCORE_CRASH                 1000.0
// #define SCORE_NEW_HANG              50.0
// #define SCORE_KNOWN_HANG_OR_TMOUT   1.0
// #define SCORE_NEW_PATH_BASE         15.0
// #define SCORE_NEW_BITS_GENERIC_BASE 2.0 // Not used directly if new_bits_type > 0 implies new path
// #define SCORE_DECAY                 -0.5
#include "afl-fuzz.h" // Ensure this includes definitions for SCORE_CRASH, etc.

// Ensure these score constants are defined (e.g., in afl-fuzz.h)
// #define SCORE_CRASH                 1000.0
// #define SCORE_NEW_HANG              50.0
// #define SCORE_KNOWN_HANG_OR_TMOUT   1.0
// #define SCORE_NEW_PATH_BASE         15.0
// #define SCORE_NEW_BITS_GENERIC_BASE 2.0 // Not used directly if new_bits_type > 0 implies new path
// #define SCORE_DECAY                 -0.5
#include "afl-fuzz.h" // Ensure this includes definitions for SCORE_CRASH, etc.

// Ensure these score constants are defined (e.g., in afl-fuzz.h)
// #define SCORE_CRASH                 1000.0
// #define SCORE_NEW_HANG              50.0
// #define SCORE_KNOWN_HANG_OR_TMOUT   1.0
// #define SCORE_NEW_PATH_BASE         15.0
// #define SCORE_NEW_BITS_GENERIC_BASE 2.0 // Not used directly if new_bits_type > 0 implies new path
// #define SCORE_DECAY                 -0.5
#include "afl-fuzz.h" // Ensure this includes definitions for SCORE_CRASH, etc.

// Ensure these score constants are defined (e.g., in afl-fuzz.h)
// #define SCORE_CRASH                 1000.0
// #define SCORE_NEW_HANG              50.0
// #define SCORE_KNOWN_HANG_OR_TMOUT   1.0
// #define SCORE_NEW_PATH_BASE         15.0
// #define SCORE_NEW_BITS_GENERIC_BASE 2.0 // Not used directly if new_bits_type > 0 implies new path
// #define SCORE_DECAY                 -0.5

u8 __attribute__((hot)) save_if_interesting(afl_state_t *afl, void *mem,
                                            u32 len, u8 fault) {

  if (unlikely(len == 0)) { 
    afl->current_execution_score_base = SCORE_DECAY; 
    return 0; 
  }

  double calculated_exec_score = SCORE_DECAY; // Default score

  if (unlikely(fault == FSRV_RUN_TMOUT && afl->afl_env.afl_ignore_timeouts)) {
    if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {
      classify_counts(&afl->fsrv);
      u64 cksum_tmp = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST); // Renamed to avoid conflict
      if (likely(afl->n_fuzz[cksum_tmp % N_FUZZ_SIZE] < 0xFFFFFFFF))
        afl->n_fuzz[cksum_tmp % N_FUZZ_SIZE]++;
    }
    afl->current_execution_score_base = SCORE_KNOWN_HANG_OR_TMOUT; // Score for ignored timeout
    return 0;
  }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits_type = 0; // 0: no new, 1: new counts, 2: new tuples
  u8  keeping = 0;
  u8  res; 
  u8  classified = 0;
  u8  is_timeout = 0; 
  u8  need_hash = 1;
  s32 fd;
  u64 cksum_fast = 0; // Renamed for AFLFast context
  u32 cksum_simplified = 0, cksum_unique = 0;
  u8  san_fault = FSRV_RUN_OK; // Initialize san_fault
  u8  san_idx = 0;
  u8  feed_san = 0;
  afl->san_case_status = 0;

  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {
    classify_counts(&afl->fsrv);
    classified = 1;
    need_hash = 0;
    cksum_fast = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    if (likely(afl->n_fuzz[cksum_fast % N_FUZZ_SIZE] < 0xFFFFFFFF))
      afl->n_fuzz[cksum_fast % N_FUZZ_SIZE]++;
  }

  // --- SAND integration ---
  if (likely(fault == afl->crash_mode)) { // Only run SAND if primary is not a crash/timeout
    if (unlikely(afl->san_binary_length)) { // Check if SAND binaries are configured
        // Store original new_bits_type before SAND potentially re-runs and modifies trace_bits
        u8 original_new_bits_type = has_new_bits_unclassified(afl, afl->virgin_bits);

        if (likely(afl->san_abstraction == SIMPLIFY_TRACE)) {
            memcpy(afl->san_fsrvs[0].trace_bits, afl->fsrv.trace_bits, afl->fsrv.map_size);
            classify_counts_mem((_AFL_INTSIZEVAR *)afl->san_fsrvs[0].trace_bits, afl->fsrv.map_size);
            simplify_trace(afl, afl->san_fsrvs[0].trace_bits);
            cksum_simplified = hash32(afl->san_fsrvs[0].trace_bits, afl->fsrv.map_size, HASH_CONST);
            if (unlikely(!bitmap_read(afl->simplified_n_fuzz, cksum_simplified))) {
                feed_san = 1;
                bitmap_set(afl->simplified_n_fuzz, cksum_simplified);
            }
        }
        if (unlikely(afl->san_abstraction == COVERAGE_INCREASE)) {
            if (unlikely(original_new_bits_type)) { feed_san = 1; } // Use original_new_bits_type
        }
        if (likely(afl->san_abstraction == UNIQUE_TRACE)) {
            cksum_unique = hash32(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST); // Hash current trace
            if (unlikely(!bitmap_read(afl->n_fuzz_dup, cksum_unique))) { // Check with unique hash
                feed_san = 1;
                bitmap_set(afl->n_fuzz_dup, cksum_unique);
            }
        }
        if (feed_san) {
            for (san_idx = 0; san_idx < afl->san_binary_length; san_idx++) {
                u32 current_len_for_sand = len;
                u8* current_mem_for_sand = mem; // Important: mem can be changed by write_to_testcase if it reallocs
                current_len_for_sand = write_to_testcase(afl, (void**)&current_mem_for_sand, current_len_for_sand, 0);
                
                u8 temp_san_fault = fuzz_run_target(afl, &afl->san_fsrvs[san_idx], afl->san_fsrvs[san_idx].exec_tmout);
                if (unlikely(temp_san_fault && fault == afl->crash_mode)) { // fault is primary run's fault
                    afl->san_case_status |= SAN_CRASH_ONLY;
                }
                if (temp_san_fault == FSRV_RUN_CRASH) {
                    san_fault = temp_san_fault; // Update san_fault if a crash is found by SAND
                    break; 
                }
                // san_fault remains FSRV_RUN_OK if no SAND crash
            }
        }
        // Restore primary fsrv trace_bits if SAND runs modified it (though fuzz_run_target should use its own fsrv)
        // This is usually not necessary as fuzz_run_target operates on the fsrv passed to it.
    }
  }
  // --- End SAND integration ---

  // --- Main Logic for Interest & Scoring ---
  if (likely(fault == afl->crash_mode)) { // Primary run was not a crash or timeout
    // Determine new coverage from the primary run's trace_bits
    if (likely(classified)) { 
      new_bits_type = has_new_bits(afl, afl->virgin_bits);
    } else {
      new_bits_type = has_new_bits_unclassified(afl, afl->virgin_bits);
      if (unlikely(new_bits_type)) { classified = 1; } 
    }

    if (likely(!new_bits_type)) { // No new coverage from primary run
      if (san_fault == FSRV_RUN_OK) { // And SAND found no crash
        calculated_exec_score = SCORE_DECAY;
        afl->current_execution_score_base = calculated_exec_score;
        return 0; 
      } else { // SAND found a bug (crash), but no new primary coverage
        afl->san_case_status |= NON_COV_INCREASE_BUG;
        fault = san_fault; // Promote SAND's fault status
        // new_bits_type remains 0
        goto may_save_fault; 
      }
    }

    // --- New coverage found by primary run ---
    calculated_exec_score = SCORE_NEW_PATH_BASE; 
    if (new_bits_type == 2) { 
      calculated_exec_score += (double)count_class_changes(afl, afl->virgin_bits);
    } else if (new_bits_type == 1) { 
      calculated_exec_score += ((double)count_new_hits(afl, afl->virgin_bits) / 10.0);
    }
    
    // If SAND also found a crash, promote fault, but score is primarily for new coverage
    if (san_fault == FSRV_RUN_CRASH) {
        fault = san_fault; 
    }
  
  save_to_queue: // Label for saving inputs that found new coverage
    afl->current_execution_score_base = calculated_exec_score; 

#ifndef SIMPLE_FILES
    if (!afl->afl_env.afl_sha1_filenames) {
      queue_fn = alloc_printf(
          "%s/queue/id:%06u,%s%s%s", afl->out_dir, afl->queued_items,
          describe_op(afl, new_bits_type + is_timeout, 
                      NAME_MAX - strlen("id:000000,")),
          afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");
    } else { 
      const char *hex = sha1_hex(mem, len);
      queue_fn = alloc_printf(
          "%s/queue/%s%s%s", afl->out_dir, hex, afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");
      ck_free((char *)hex);
    }
#else
    queue_fn = alloc_printf(
        "%s/queue/id_%06u%s%s", afl->out_dir, afl->queued_items,
        afl->file_extension ? "." : "",
        afl->file_extension ? (const char *)afl->file_extension : "");
#endif                                                    
    fd = permissive_create(afl, queue_fn);
    if (likely(fd >= 0)) {
      ck_write(fd, mem, len, queue_fn);
      close(fd);
    }

    add_to_queue(afl, queue_fn, len, 0); 

    if (unlikely(afl->fuzz_mode) && likely(afl->switch_fuzz_mode && !afl->non_instrumented_mode)) { 
      if (afl->afl_env.afl_no_ui) {
        ACTF("New coverage found, switching back to exploration mode.");
      }
      afl->fuzz_mode = 0; 
    }

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {
      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {
        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {
          const char *ptr = el->afl_custom_introspection(el->data);
          if (ptr != NULL && *ptr != 0) {
            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);
          }
        }
      });
    } else if (afl->mutation[0] != 0) {
      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);
    }
#endif

    if (new_bits_type == 2) { 
      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;
    }

    if (unlikely(need_hash && new_bits_type)) { 
      if(!classified) classify_counts(&afl->fsrv); 
      afl->queue_top->exec_cksum =
          hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      // need_hash = 0; // Not strictly necessary if only used once
    }

    if (likely(cksum_fast)) { 
      afl->queue_top->n_fuzz_entry = cksum_fast % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;
    }

    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);
    if (unlikely(res == FSRV_RUN_ERROR)) {
      afl->current_execution_score_base = SCORE_DECAY * 100; 
      FATAL("Unable to execute target application");
    }
    if (likely(afl->q_testcase_max_cache_size)) {
      queue_testcase_store_mem(afl, afl->queue_top, mem);
    }
    keeping = 1; 
    return keeping; 
  }

  // --- If primary execution was a crash or timeout (fault != afl->crash_mode from start, or from NON_COV_INCREASE_BUG) ---
may_save_fault:
  switch (fault) {
    case FSRV_RUN_TMOUT:
      ++afl->total_tmouts;
      // Check if this timeout path is new in virgin_tmout
      // simplify_trace should be called before has_new_bits for virgin_tmout
      if (likely(!afl->non_instrumented_mode)) {
          if (unlikely(!classified)) { // Ensure trace is classified if not already
              classify_counts(&afl->fsrv);
              // classified = 1; // This flag is mostly for primary coverage logic
          }
          simplify_trace(afl, afl->fsrv.trace_bits); // Simplify for unique hang check
      }
      calculated_exec_score = (afl->saved_hangs < KEEP_UNIQUE_HANG && (afl->non_instrumented_mode || has_new_bits(afl, afl->virgin_tmout))) ? SCORE_NEW_HANG : SCORE_KNOWN_HANG_OR_TMOUT;
      calculated_exec_score += 10.0 / (afl->total_tmouts + 1.0); 
      afl->current_execution_score_base = calculated_exec_score;
      
      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; } 
      
      // Re-check virgin_tmout after potential simplification if not done above for score
      if (likely(!afl->non_instrumented_mode) && !has_new_bits(afl, afl->virgin_tmout)) {
          // If simplify_trace was already called, this check is redundant unless classify_counts changed things.
          // To be safe, ensure trace is simplified before this check if not already.
          return keeping; 
      }
      is_timeout = 0x80; 
#ifdef INTROSPECTION
      // ... (introspection logic unchanged) ...
#endif
      if (afl->fsrv.exec_tmout < afl->hang_tmout) {
        u8  new_fault_rerun; 
        u32 tmp_len_rerun = len; 
        u8* mem_rerun = mem;     
        tmp_len_rerun = write_to_testcase(afl, (void**)&mem_rerun, tmp_len_rerun, 0);
        if(!tmp_len_rerun) tmp_len_rerun = write_to_testcase(afl, (void**)&mem_rerun, len, 1); 

        new_fault_rerun = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        // Note: re-running might change afl->fsrv.trace_bits. If score depends on this, it might need re-eval.
        if (!afl->stop_soon && new_fault_rerun == FSRV_RUN_CRASH) {
          fault = FSRV_RUN_CRASH; 
          // Score for this path will be re-evaluated as crash in the CRASH case
          goto keep_as_crash; 
        }
        if (afl->stop_soon || new_fault_rerun != FSRV_RUN_TMOUT) {
          if (afl->afl_env.afl_keep_timeouts) {
            ++afl->saved_tmouts; 
            // If this timeout is saved to queue (less common for non-unique hangs)
            // goto save_to_queue; // This would require 'keeping = 1' and setting score for new path
          } else {
            return keeping; 
          }
        }
      }
#ifndef SIMPLE_FILES
      if (!afl->afl_env.afl_sha1_filenames) {
        snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s%s%s", afl->out_dir,
                 afl->saved_hangs,
                 describe_op(afl, 0 + is_timeout, NAME_MAX - strlen("id:000000,")),
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
      } else { 
        const char *hex = sha1_hex(mem, len);
        snprintf(fn, PATH_MAX, "%s/hangs/%s%s%s", afl->out_dir, hex,
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
        ck_free((char *)hex);
      }
#else
      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu%s%s", afl->out_dir, afl->saved_hangs,
               afl->file_extension ? "." : "",
               afl->file_extension ? (const char *)afl->file_extension : "");
#endif                                                   
      ++afl->saved_hangs;
      afl->last_hang_time = get_cur_time();
      break; 

    case FSRV_RUN_CRASH:
    keep_as_crash: 
      ++afl->total_crashes;
      calculated_exec_score = SCORE_CRASH; 
      afl->current_execution_score_base = calculated_exec_score;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }
      if (likely(!afl->non_instrumented_mode)) {
        if (unlikely(!classified)) { 
          classify_counts(&afl->fsrv);
        }
        simplify_trace(afl, afl->fsrv.trace_bits); 
        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; } 
      }
      if (unlikely(!afl->saved_crashes) && (afl->afl_env.afl_no_crash_readme != 1)) {
        write_crash_readme(afl);
      }
#ifndef SIMPLE_FILES
      if (!afl->afl_env.afl_sha1_filenames) {
        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s%s%s",
                 afl->out_dir, afl->saved_crashes, afl->fsrv.last_kill_signal,
                 describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")), 
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
      } else { 
        const char *hex = sha1_hex(mem, len);
        snprintf(fn, PATH_MAX, "%s/crashes/%s%s%s", afl->out_dir, hex,
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
        ck_free((char *)hex);
      }
#else
      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u%s%s", afl->out_dir, 
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               afl->file_extension ? "." : "",
               afl->file_extension ? (const char *)afl->file_extension : "");
#endif                                                   
      ++afl->saved_crashes;
#ifdef INTROSPECTION
      // ... 
#endif
      if (unlikely(afl->infoexec)) {
        (void)(system(afl->infoexec) + 1);
      }
      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;
      break; 

    case FSRV_RUN_ERROR:
      afl->current_execution_score_base = SCORE_DECAY * 100.0; 
      FATAL("Unable to execute target application (FSRV_RUN_ERROR)");
      return keeping; // Unreachable

    default: 
      afl->current_execution_score_base = SCORE_DECAY;
      return keeping;
  }

  // This part is reached if a crash or hang file was written (but not necessarily added to queue)
  fd = permissive_create(afl, fn); 
  if (fd >= 0) {
    ck_write(fd, mem, len, fn);
    close(fd);
  }

#ifdef __linux__ 
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {
    u8 fn_log[PATH_MAX];
    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }
    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string,
        afl->fsrv.nyx_aux_string_len);
    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);
  }
#endif
  // afl->current_execution_score_base should have been set within the switch case.
  return keeping; 
}
