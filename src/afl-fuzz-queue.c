/*
   american fuzzy lop++ - queue relates routines
   ---------------------------------------------

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
#include <ctype.h>
#include <math.h>

#ifdef _STANDALONE_MODULE
void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  return;

}

void run_afl_custom_queue_new_entry(afl_state_t *afl, struct queue_entry *q,
                                    u8 *a, u8 *b) {

  return;

}

#endif

/* select next queue entry based on alias algo - fast! */

inline u32 select_next_queue_entry(afl_state_t *afl) {

  u32    s = rand_below(afl, afl->queued_items);
  double p = rand_next_percent(afl);

  /*
  fprintf(stderr, "select: p=%f s=%u ... p < prob[s]=%f ? s=%u : alias[%u]=%u"
  " ==> %u\n", p, s, afl->alias_probability[s], s, s, afl->alias_table[s], p <
  afl->alias_probability[s] ? s : afl->alias_table[s]);
  */

  return (p < afl->alias_probability[s] ? s : afl->alias_table[s]);

}

/* create the alias table that allows weighted random selection - expensive */

void create_alias_table(afl_state_t *afl) {

  u32    n = afl->queued_items, i = 0, nSmall = 0, nLarge = n - 1;
  double sum = 0;

  double *P = (double *)afl_realloc(AFL_BUF_PARAM(out), n * sizeof(double));
  u32 *Small = (int *)afl_realloc(AFL_BUF_PARAM(out_scratch), n * sizeof(u32));
  u32 *Large = (int *)afl_realloc(AFL_BUF_PARAM(in_scratch), n * sizeof(u32));

  afl->alias_table =
      (u32 *)afl_realloc((void **)&afl->alias_table, n * sizeof(u32));
  afl->alias_probability = (double *)afl_realloc(
      (void **)&afl->alias_probability, n * sizeof(double));

  if (!P || !Small || !Large || !afl->alias_table || !afl->alias_probability) {

    FATAL("could not acquire memory for alias table");

  }

  memset((void *)afl->alias_probability, 0, n * sizeof(double));
  memset((void *)afl->alias_table, 0, n * sizeof(u32));
  memset((void *)Small, 0, n * sizeof(u32));
  memset((void *)Large, 0, n * sizeof(u32));

  if (likely(afl->schedule < RARE)) {

    double avg_exec_us = 0.0;
    double avg_bitmap_size = 0.0;
    double avg_len = 0.0;
    u32    active = 0;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      // disabled entries might have timings and bitmap values
      if (likely(!q->disabled)) {

        avg_exec_us += q->exec_us;
        avg_bitmap_size += log(q->bitmap_size);
        avg_len += q->len;
        ++active;

      }

    }

    avg_exec_us /= active;
    avg_bitmap_size /= active;
    avg_len /= active;

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        double weight = 1.0;
        {  // inline does result in a compile error with LTO, weird

          if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

            u32 hits = afl->n_fuzz[q->n_fuzz_entry];
            if (likely(hits)) { weight /= (log10(hits) + 1); }

          }

          if (likely(afl->schedule < RARE)) {

            double t = q->exec_us / avg_exec_us;

            if (likely(t < 0.1)) {

              // nothing

            } else if (likely(t <= 0.25)) {

              weight *= 0.95;

            } else if (likely(t <= 0.5)) {

              // nothing

            } else if (likely(t <= 0.75)) {

              weight *= 1.05;

            } else if (likely(t <= 1.0)) {

              weight *= 1.1;

            } else if (likely(t < 1.25)) {

              weight *= 0.2;  // WTF ??? makes no sense

            } else if (likely(t <= 1.5)) {

              // nothing

            } else if (likely(t <= 2.0)) {

              weight *= 1.1;

            } else if (likely(t <= 2.5)) {

            } else if (likely(t <= 5.0)) {

              weight *= 1.15;

            } else if (likely(t <= 20.0)) {

              weight *= 1.1;
              // else nothing

            }

          }

          double l = q->len / avg_len;
          if (likely(l < 0.1)) {

            weight *= 0.5;

          } else if (likely(l <= 0.5)) {

            // nothing

          } else if (likely(l <= 1.25)) {

            weight *= 1.05;

          } else if (likely(l <= 1.75)) {

            // nothing

          } else if (likely(l <= 2.0)) {

            weight *= 0.95;

          } else if (likely(l <= 5.0)) {

            // nothing

          } else if (likely(l <= 10.0)) {

            weight *= 1.05;

          } else {

            weight *= 1.15;

          }

          double bms = q->bitmap_size / avg_bitmap_size;
          if (likely(bms < 0.1)) {

            weight *= 0.01;

          } else if (likely(bms <= 0.25)) {

            weight *= 0.55;

          } else if (likely(bms <= 0.5)) {

            // nothing

          } else if (likely(bms <= 0.75)) {

            weight *= 1.2;

          } else if (likely(bms <= 1.25)) {

            weight *= 1.3;

          } else if (likely(bms <= 1.75)) {

            weight *= 1.25;

          } else if (likely(bms <= 2.0)) {

            // nothing

          } else if (likely(bms <= 2.5)) {

            weight *= 1.3;

          } else {

            weight *= 0.75;

          }

          if (unlikely(!q->was_fuzzed)) { weight *= 2.5; }
          if (unlikely(q->fs_redundant)) { weight *= 0.75; }

        }

        q->weight = weight;
        q->perf_score = calculate_score(afl, q);
        sum += q->weight;

      }

    }

    if (unlikely(afl->schedule == MMOPT) && afl->queued_discovered) {

      u32 cnt = afl->queued_discovered >= 5 ? 5 : afl->queued_discovered;

      for (i = n - cnt; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];

        if (likely(!q->disabled)) { q->weight *= 2.0; }

      }

    }

    for (i = 0; i < n; i++) {

      // weight is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->weight * n) / sum;

      }

    }

  } else {

    for (i = 0; i < n; i++) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(!q->disabled)) {

        q->perf_score = calculate_score(afl, q);
        sum += q->perf_score;

      }

    }

    for (i = 0; i < n; i++) {

      // perf_score is always 0 for disabled entries
      if (unlikely(afl->queue_buf[i]->disabled)) {

        P[i] = 0;

      } else {

        P[i] = (afl->queue_buf[i]->perf_score * n) / sum;

      }

    }

  }

  // Done collecting weightings in P, now create the arrays.

  for (s32 j = (s32)(n - 1); j >= 0; j--) {

    if (P[j] < 1) {

      Small[nSmall++] = (u32)j;

    } else {

      Large[nLarge--] = (u32)j;

    }

  }

  while (nSmall && nLarge != n - 1) {

    u32 small = Small[--nSmall];
    u32 large = Large[++nLarge];

    afl->alias_probability[small] = P[small];
    afl->alias_table[small] = large;

    P[large] = P[large] - (1 - P[small]);

    if (P[large] < 1) {

      Small[nSmall++] = large;

    } else {

      Large[nLarge--] = large;

    }

  }

  while (nSmall) {

    afl->alias_probability[Small[--nSmall]] = 1;

  }

  while (nLarge != n - 1) {

    afl->alias_probability[Large[++nLarge]] = 1;

  }

  afl->reinit_table = 0;

  /*
  #ifdef INTROSPECTION
    u8 fn[PATH_MAX];
    snprintf(fn, PATH_MAX, "%s/introspection_corpus.txt", afl->out_dir);
    FILE *f = fopen(fn, "a");
    if (f) {

      for (i = 0; i < n; i++) {

        struct queue_entry *q = afl->queue_buf[i];
        fprintf(
            f,
            "entry=%u name=%s favored=%s variable=%s disabled=%s len=%u "
            "exec_us=%u "
            "bitmap_size=%u bitsmap_size=%u tops=%u weight=%f perf_score=%f\n",
            i, q->fname, q->favored ? "true" : "false",
            q->var_behavior ? "true" : "false", q->disabled ? "true" : "false",
            q->len, (u32)q->exec_us, q->bitmap_size, q->bitsmap_size, q->tc_ref,
            q->weight, q->perf_score);

      }

      fprintf(f, "\n");
      fclose(f);

    }

  #endif
  */
  /*
  fprintf(stderr, "  entry  alias  probability  perf_score   weight
  filename\n"); for (i = 0; i < n; ++i) fprintf(stderr, "  %5u  %5u  %11u
  %0.9f  %0.9f  %s\n", i, afl->alias_table[i], afl->alias_probability[i],
  afl->queue_buf[i]->perf_score, afl->queue_buf[i]->weight,
            afl->queue_buf[i]->fname);
  */

}

/* Mark deterministic checks as done for a particular queue entry. We use the
   .state file to avoid repeating deterministic fuzzing when resuming aborted
   scans. */

void mark_as_det_done(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  s32  fd;

  snprintf(fn, PATH_MAX, "%s/queue/.state/deterministic_done/%s", afl->out_dir,
           strrchr((char *)q->fname, '/') + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }
  close(fd);

  q->passed_det = 1;

}

/* Mark as variable. Create symlinks if possible to make it easier to examine
   the files. */

void mark_as_variable(afl_state_t *afl, struct queue_entry *q) {

  char fn[PATH_MAX];
  char ldest[PATH_MAX];

  char *fn_name = strrchr((char *)q->fname, '/') + 1;

  sprintf(ldest, "../../%s", fn_name);
  sprintf(fn, "%s/queue/.state/variable_behavior/%s", afl->out_dir, fn_name);

  if (symlink(ldest, fn)) {

    s32 fd = permissive_create(afl, fn);
    if (fd >= 0) { close(fd); }

  }

  q->var_behavior = 1;

}

/* Mark / unmark as redundant (edge-only). This is not used for restoring state,
   but may be useful for post-processing datasets. */

void mark_as_redundant(afl_state_t *afl, struct queue_entry *q, u8 state) {

  if (likely(state == q->fs_redundant)) { return; }

  char fn[PATH_MAX];

  q->fs_redundant = state;

  if (likely(q->fs_redundant)) {

    if (unlikely(q->trace_mini)) {

      ck_free(q->trace_mini);
      q->trace_mini = NULL;

    }

  }

  sprintf(fn, "%s/queue/.state/redundant_edges/%s", afl->out_dir,
          strrchr((char *)q->fname, '/') + 1);

  if (state) {

    s32 fd;

    if (unlikely(afl->afl_env.afl_disable_redundant)) { q->disabled = 1; }
    fd = permissive_create(afl, fn);
    if (fd >= 0) { close(fd); }

  } else {

    if (unlink(fn)) {                 /*PFATAL("Unable to remove '%s'", fn);*/

    }

  }

}

/* check if pointer is ascii or UTF-8 */

u8 check_if_text_buf(u8 *buf, u32 len) {

  u32 offset = 0, ascii = 0, utf8 = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      continue;

    }

    offset++;

  }

  return (utf8 > ascii ? utf8 : ascii);

}

/* check if queue entry is ascii or UTF-8 */

static u8 check_if_text(afl_state_t *afl, struct queue_entry *q) {

  if (q->len < AFL_TXT_MIN_LEN || q->len < AFL_TXT_MAX_LEN) return 0;

  u8     *buf;
  int     fd;
  u32     len = q->len, offset = 0, ascii = 0, utf8 = 0;
  ssize_t comp;

  if (len >= MAX_FILE) len = MAX_FILE - 1;
  if ((fd = open((char *)q->fname, O_RDONLY)) < 0) return 0;
  buf = (u8 *)afl_realloc(AFL_BUF_PARAM(in_scratch), len + 1);
  comp = read(fd, buf, len);
  close(fd);
  if (comp != (ssize_t)len) return 0;
  buf[len] = 0;

  while (offset < len) {

    // ASCII: <= 0x7F to allow ASCII control characters
    if ((buf[offset + 0] == 0x09 || buf[offset + 0] == 0x0A ||
         buf[offset + 0] == 0x0D ||
         (0x20 <= buf[offset + 0] && buf[offset + 0] <= 0x7E))) {

      offset++;
      utf8++;
      ascii++;
      continue;

    }

    if (isascii((int)buf[offset]) || isprint((int)buf[offset])) {

      ascii++;
      // we continue though as it can also be a valid utf8

    }

    // non-overlong 2-byte
    if (len - offset > 1 &&
        ((0xC2 <= buf[offset + 0] && buf[offset + 0] <= 0xDF) &&
         (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF))) {

      offset += 2;
      utf8++;
      comp--;
      continue;

    }

    // excluding overlongs
    if ((len - offset > 2) &&
        ((buf[offset + 0] == 0xE0 &&
          (0xA0 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // straight 3-byte
         (((0xE1 <= buf[offset + 0] && buf[offset + 0] <= 0xEC) ||
           buf[offset + 0] == 0xEE || buf[offset + 0] == 0xEF) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] &&
           buf[offset + 2] <= 0xBF)) ||  // excluding surrogates
         (buf[offset + 0] == 0xED &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x9F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF)))) {

      offset += 3;
      utf8++;
      comp -= 2;
      continue;

    }

    // planes 1-3
    if ((len - offset > 3) &&
        ((buf[offset + 0] == 0xF0 &&
          (0x90 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] &&
           buf[offset + 3] <= 0xBF)) ||  // planes 4-15
         ((0xF1 <= buf[offset + 0] && buf[offset + 0] <= 0xF3) &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0xBF) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)) ||  // plane 16
         (buf[offset + 0] == 0xF4 &&
          (0x80 <= buf[offset + 1] && buf[offset + 1] <= 0x8F) &&
          (0x80 <= buf[offset + 2] && buf[offset + 2] <= 0xBF) &&
          (0x80 <= buf[offset + 3] && buf[offset + 3] <= 0xBF)))) {

      offset += 4;
      utf8++;
      comp -= 3;
      continue;

    }

    offset++;

  }

  u32 percent_utf8 = (utf8 * 100) / comp;
  u32 percent_ascii = (ascii * 100) / len;

  if (percent_utf8 >= percent_ascii && percent_utf8 >= AFL_TXT_MIN_PERCENT)
    return 2;
  if (percent_ascii >= AFL_TXT_MIN_PERCENT) return 1;
  return 0;

}

/* Append new test case to the queue. */

void add_to_queue(afl_state_t *afl, u8 *fname, u32 len, u8 passed_det) {

  struct queue_entry *q =
      (struct queue_entry *)ck_alloc(sizeof(struct queue_entry));

  q->fname = fname;
  q->len = len;
  q->depth = afl->cur_depth + 1;
  q->passed_det = passed_det;
  q->trace_mini = NULL;
  q->testcase_buf = NULL;
  q->mother = afl->queue_cur;
  q->weight = 1.0;
  q->perf_score = 100;

#ifdef INTROSPECTION
  q->bitsmap_size = afl->bitsmap_size;
#endif

  if (q->depth > afl->max_depth) { afl->max_depth = q->depth; }

  if (afl->queue_top) {

    afl->queue_top = q;

  } else {

    afl->queue = afl->queue_top = q;

  }

  if (likely(q->len > 4)) { ++afl->ready_for_splicing_count; }

  ++afl->queued_items;
  ++afl->active_items;
  ++afl->pending_not_fuzzed;

  afl->cycles_wo_finds = 0;

  struct queue_entry **queue_buf = (struct queue_entry **)afl_realloc(
      AFL_BUF_PARAM(queue), afl->queued_items * sizeof(struct queue_entry *));
  if (unlikely(!queue_buf)) { PFATAL("alloc"); }
  queue_buf[afl->queued_items - 1] = q;
  q->id = afl->queued_items - 1;

  u64 cur_time = get_cur_time();

  if (likely(afl->start_time) &&
      unlikely(afl->longest_find_time < cur_time - afl->last_find_time)) {

    if (unlikely(!afl->last_find_time)) {

      afl->longest_find_time = cur_time - afl->start_time;

    } else {

      afl->longest_find_time = cur_time - afl->last_find_time;

    }

  }

  afl->last_find_time = cur_time;

  if (afl->custom_mutators_count) {

    /* At the initialization stage, queue_cur is NULL */
    if (afl->queue_cur && !afl->syncing_party) {

      run_afl_custom_queue_new_entry(afl, q, fname, afl->queue_cur->fname);

    }

  }

  /* only redqueen currently uses is_ascii */
  if (unlikely(afl->shm.cmplog_mode && !q->is_ascii)) {

    q->is_ascii = check_if_text(afl, q);

  }

  q->skipdet_e = (struct skipdet_entry *)ck_alloc(sizeof(struct skipdet_entry));

}

/* Destroy the entire queue. */

void destroy_queue(afl_state_t *afl) {

  u32                 i;
  struct queue_entry *q;

  for (i = 0; i < afl->queued_items; i++) {

    q = afl->queue_buf[i];
    ck_free(q->fname);
    ck_free(q->trace_mini);
    if (q->skipdet_e) {

      if (q->skipdet_e->done_inf_map) ck_free(q->skipdet_e->done_inf_map);
      if (q->skipdet_e->skip_eff_map) ck_free(q->skipdet_e->skip_eff_map);

      ck_free(q->skipdet_e);

    }

    ck_free(q);

  }

}

/* When we bump into a new path, we call this to see if the path appears
   more "favorable" than any of the existing ones. The purpose of the
   "favorables" is to have a minimal set of paths that trigger all the bits
   seen in the bitmap so far, and focus on fuzzing them at the expense of
   the rest.

   The first step of the process is to maintain a list of afl->top_rated[]
   entries for every byte in the bitmap. We win that slot if there is no
   previous contender, or if the contender has a more favorable speed x size
   factor. */

void update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {

  u32 i;
  u64 fav_factor;
  u64 fuzz_p2;

  if (unlikely(afl->schedule >= FAST && afl->schedule < RARE)) {

    fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

  } else if (unlikely(afl->schedule == RARE)) {

    fuzz_p2 = next_pow2(afl->n_fuzz[q->n_fuzz_entry]);

  } else {

    fuzz_p2 = q->fuzz_level;

  }

  if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

    fav_factor = q->len << 2;

  } else {

    fav_factor = q->exec_us * q->len;

  }

  /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
     winner, and how it compares to us. */
  for (i = 0; i < afl->fsrv.map_size; ++i) {

    if (afl->fsrv.trace_bits[i]) {

      if (afl->top_rated[i]) {

        /* Faster-executing or smaller test cases are favored. */
        u64 top_rated_fav_factor;
        u64 top_rated_fuzz_p2;

        if (unlikely(afl->schedule >= FAST && afl->schedule < RARE)) {

          top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison

        } else if (unlikely(afl->schedule == RARE)) {

          top_rated_fuzz_p2 =
              next_pow2(afl->n_fuzz[afl->top_rated[i]->n_fuzz_entry]);

        } else {

          top_rated_fuzz_p2 = afl->top_rated[i]->fuzz_level;

        }

        if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {

          top_rated_fav_factor = afl->top_rated[i]->len << 2;

        } else {

          top_rated_fav_factor =
              afl->top_rated[i]->exec_us * afl->top_rated[i]->len;

        }

        if (likely(fuzz_p2 > top_rated_fuzz_p2)) { continue; }

        if (likely(fav_factor > top_rated_fav_factor)) { continue; }

        /* Looks like we're going to win. Decrease ref count for the
           previous winner, discard its afl->fsrv.trace_bits[] if necessary. */

        if (!--afl->top_rated[i]->tc_ref) {

          ck_free(afl->top_rated[i]->trace_mini);
          afl->top_rated[i]->trace_mini = NULL;

        }

      }

      /* Insert ourselves as the new winner. */

      afl->top_rated[i] = q;
      ++q->tc_ref;

      if (!q->trace_mini) {

        u32 len = (afl->fsrv.map_size >> 3);
        q->trace_mini = (u8 *)ck_alloc(len);
        minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);

      }

      afl->score_changed = 1;

    }

  }

}

typedef struct {
    u32 index;  // Index into fsrv->state_info
    u64 score;  // The total_score of the state (for heap ordering)
} candidate_t;

// Swap function for candidate_t elements
static void swap_candidates(candidate_t *a, candidate_t *b) {
    candidate_t temp = *a;
    *a = *b;
    *b = temp;
}

// Min-Heapify for the *candidate* heap (C version).
static void min_heapify_candidates(candidate_t *arr, u32 heap_size, u32 index) {
    u32 smallest = index;
    u32 left = 2 * index + 1;
    u32 right = 2 * index + 2;

    if (left < heap_size && arr[left].score < arr[smallest].score) {
        smallest = left;
    }
    if (right < heap_size && arr[right].score < arr[smallest].score) {
        smallest = right;
    }

    if (smallest != index) {
        swap_candidates(&arr[index], &arr[smallest]);
        min_heapify_candidates(arr, heap_size, smallest); // Recursive call
    }
}

// --- The get_top_states Function ---

state_info_t **get_top_states(afl_forkserver_t *fsrv, double percentage, u32 *count) {

    if (!fsrv || !fsrv->state_info || fsrv->state_heap_size == 0 || percentage <= 0.0 || percentage > 1.0) {
        *count = 0;
        return NULL;
    }

    u32 num_to_retrieve = (u32)(fsrv->state_heap_size * percentage);
    if (num_to_retrieve == 0 && fsrv->state_heap_size > 0 && percentage > 0.0) {
         num_to_retrieve = 1; // Ensure at least 1 if possible
    } else if (num_to_retrieve == 0) {
         *count = 0;
         return NULL;
    }
    num_to_retrieve = MIN(num_to_retrieve, fsrv->state_heap_size);

    state_info_t **top_states = (state_info_t **)ck_alloc(sizeof(state_info_t *) * num_to_retrieve);
    if (!top_states) {
      PFATAL("failed to allocate top_states");
    }

    // Temporary min-heap of size num_to_retrieve (K)
    candidate_t *candidates = (candidate_t *)ck_alloc(sizeof(candidate_t) * num_to_retrieve);
    if (!candidates) {
        ck_free(top_states);
        PFATAL("failed to allocate candidates for top-k");
    }
    u32 candidates_size = 0;

    // Iterate through ALL states in the original max-heap array
    for (u32 i = 0; i < fsrv->state_heap_size; ++i) {
        u64 current_score = fsrv->state_info[i].total_score;

        if (candidates_size < num_to_retrieve) {
            // Heap is not full, add the current element and bubble UP (min-heap)
            candidates[candidates_size].index = i;
            candidates[candidates_size].score = current_score;
            u32 k = candidates_size;
            candidates_size++;
            // Bubble up
            while (k != 0 && candidates[(k - 1) / 2].score > candidates[k].score) {
                swap_candidates(&candidates[(k - 1) / 2], &candidates[k]);
                k = (k - 1) / 2;
            }
        } else if (current_score > candidates[0].score) {
            // Heap is full, but current state is better than the smallest in the heap
            // Replace the root (smallest) and heapify DOWN
            candidates[0].index = i;
            candidates[0].score = current_score;
            min_heapify_candidates(candidates, candidates_size, 0);
        }
    }

    // Now, the 'candidates' min-heap holds the indices/scores of the top K states.
    // Extract the pointers to the actual state_info_t structs.
    u32 num_retrieved = candidates_size; // Actual number found
    for (u32 i = 0; i < num_retrieved; ++i) {
        top_states[i] = &fsrv->state_info[candidates[i].index];
    }

    *count = num_retrieved;
    ck_free(candidates); // Free the temporary heap.
    return top_states;
}

/* The second part of the mechanism discussed above is a routine that
   goes over afl->top_rated[] entries, and then sequentially grabs winners for
   previously-unseen bytes (temp_v) and marks them as favored, at least
   until the next run. The favored entries are given more air time during
   all fuzzing steps. */
#ifndef STATE_BASED_CULLING_PROB
#define STATE_BASED_CULLING_PROB 50
#endif

#define MAX_SEEDS_TO_FAVOR_PER_STATE 4

#include "afl-state-seed-heap.h"
void cull_queue(afl_state_t *afl) {

  if (rand_below(afl, 100) < STATE_BASED_CULLING_PROB) { // Check probability
    /* --- New State-Based Favoring Logic --- */
    // ACTF("Attempting state-based queue culling (top %u seeds per state).", MAX_SEEDS_TO_FAVOR_PER_STATE);

    if (!afl->fsrv.state_info) {
      WARNF("State-based culling skipped: state_info not initialized.");
      return;
    }

    u32 top_states_count = 0;
    double top_state_percentage = 0.003; 

    state_info_t **top_states =
        get_top_states(&afl->fsrv, top_state_percentage, &top_states_count);

    // Reset favored status for all queue entries before applying new logic
    for (u32 i = 0; i < afl->queued_items; i++) {
      if (afl->queue_buf[i]) { afl->queue_buf[i]->favored = 0; }
    }
    afl->queued_favored = 0;
    afl->pending_favored = 0;
    afl->smallest_favored = -1;

    if (!top_states || top_states_count == 0) {
      WARNF("State-based culling: No top states found or allocation failed.");
      if (top_states) ck_free(top_states);
      return;
    }

    // Estimate max possible seeds to favor.
    // Each top state can contribute up to MAX_SEEDS_TO_FAVOR_PER_STATE seeds.
    u32 max_possible_favored_seeds = top_states_count * MAX_SEEDS_TO_FAVOR_PER_STATE;
    if (max_possible_favored_seeds == 0 && top_states_count > 0 && MAX_SEEDS_TO_FAVOR_PER_STATE > 0) { 
        // This case should ideally not be hit if MAX_SEEDS_TO_FAVOR_PER_STATE > 0
        max_possible_favored_seeds = top_states_count; 
    }
    if (max_possible_favored_seeds == 0) { // If still zero, means no states or no seeds to favor
        ck_free(top_states);
        WARNF("State-based culling: max_possible_favored_seeds is 0.");
        return;
    }


    u32 *favored_seed_ids = (u32 *)ck_alloc(sizeof(u32) * max_possible_favored_seeds);
    // ck_alloc PFATALs on failure

    u32 actual_favored_count = 0;

    // Collect the top N seeds from each top state
    for (u32 i = 0; i < top_states_count; i++) {
      state_info_t *current_state = top_states[i];

      if (current_state && current_state->heap_size > 0) {
        // Create a temporary copy of the state's seed heap to extract from
        // This is crucial so we don't modify the actual state's seed heap
        seed_heap_for_state_t temp_seed_heap;
        
        // Ensure current_state->heap_size does not exceed the capacity of temp_seed_heap.entries
        // Assumes MAX_TOP_SEEDS (capacity of current_state->top_seeds) is >= current_state->heap_size
        // and MAX_SEEDS_PER_STATE_HEAP (capacity of temp_seed_heap.entries) is also >= current_state->heap_size.
        // Ideally, MAX_TOP_SEEDS == MAX_SEEDS_PER_STATE_HEAP.
        u32 seeds_to_copy = MIN(current_state->heap_size, MAX_SEEDS_PER_STATE_HEAP);
        
        // Assuming seed_entry_t (in state_info_t) and seed_entry_for_state_t (in seed_heap_for_state_t)
        // are layout-compatible for the 'queue_id' and 'score' fields.
        memcpy(temp_seed_heap.entries, current_state->top_seeds, sizeof(seed_entry_t) * seeds_to_copy);
        temp_seed_heap.count = seeds_to_copy;

        // Extract up to MAX_SEEDS_TO_FAVOR_PER_STATE from the temporary heap
        for (u32 j = 0; j < MAX_SEEDS_TO_FAVOR_PER_STATE; ++j) {
          if (temp_seed_heap.count == 0) break; // No more seeds in this state's temp heap

          seed_entry_for_state_t best_seed_entry = extract_best_seed_from_state_heap(&temp_seed_heap);
          
          // Use .queue_id as returned by extract_best_seed_from_state_heap
          u32 current_best_seed_id = best_seed_entry.queue_id; 

          // Check for invalid seed (e.g., if heap was empty or error during extraction)
          if (best_seed_entry.score < 0 && current_best_seed_id == 0) { // Check for dummy/error entry
              WARNF("Extracted invalid seed entry from temp heap for state %u", current_state->state_id);
              continue; // Skip this invalid entry
          }


          // Prevent adding duplicate seed IDs to our overall favored list
          u8  already_added = 0;
          for (u32 k = 0; k < actual_favored_count; ++k) {
            if (favored_seed_ids[k] == current_best_seed_id) {
              already_added = 1;
              break;
            }
          }

          if (!already_added && actual_favored_count < max_possible_favored_seeds) {
            favored_seed_ids[actual_favored_count++] = current_best_seed_id;
          } else if (!already_added && actual_favored_count >= max_possible_favored_seeds) {
            // This should not happen if max_possible_favored_seeds is calculated correctly
            // and we break the inner loop if actual_favored_count reaches max.
            // However, as a safeguard:
            WARNF("Max possible favored seeds limit reached, cannot add more.");
            break; // Break from inner loop (j)
          }
        } // End loop for extracting top N seeds from a state
      }
      if (actual_favored_count >= max_possible_favored_seeds) break; // Break outer loop if overall limit reached
    }
    ck_free(top_states);

    // Mark the collected unique seeds as favored
    for (u32 i = 0; i < actual_favored_count; i++) {
      u32 target_id = favored_seed_ids[i];
      struct queue_entry *q_found = NULL;

      for (u32 queue_idx = 0; queue_idx < afl->queued_items; ++queue_idx) {
        if (afl->queue_buf[queue_idx] &&
            afl->queue_buf[queue_idx]->id == target_id) {
          q_found = afl->queue_buf[queue_idx];
          break;
        }
      }

      if (q_found) {
        if (!q_found->favored && !q_found->disabled) {
          q_found->favored = 1;
          afl->queued_favored++;
          if (!q_found->was_fuzzed) {
            ++afl->pending_favored;
            if (unlikely(afl->smallest_favored < 0) ||
                q_found->id < (u32)afl->smallest_favored) {
              afl->smallest_favored = (s64)q_found->id;
            }
          }
        }
      } else {
         //WARNF("State-favored seed ID %u not found in current queue!", target_id);
      }
    }
    ck_free(favored_seed_ids);

    // Mark entries not favored in this pass as redundant
    for (u32 i = 0; i < afl->queued_items; i++) {
      if (afl->queue_buf[i] && likely(!afl->queue_buf[i]->disabled)) {
        mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);
      }
    }

    if (actual_favored_count > 0 || afl->queued_favored > 0) {
        afl->score_changed = 1; 
    }
    afl->reinit_table = 1;  

    // OKF("State-based culling (top %u per state) resulted in %u unique seeds favored.", MAX_SEEDS_TO_FAVOR_PER_STATE, actual_favored_count);

  } else {
    /* --- Original AFL++ Bitmap-Based Culling Logic --- */
    // ACTF("Attempting original bitmap-based queue culling.");

    if (likely(!afl->score_changed || afl->non_instrumented_mode)) { return; }

    u32 len = (afl->fsrv.map_size >> 3); 
    u32 i;
    u8 *temp_v = afl->map_tmp_buf; 

    afl->score_changed = 0; 
    memset(temp_v, 255, len); 

    afl->queued_favored = 0;  
    afl->pending_favored = 0;

    for (i = 0; i < afl->queued_items; i++) {
      if (afl->queue_buf[i]) { 
          afl->queue_buf[i]->favored = 0;
      }
    }

    afl->smallest_favored = -1; 

    for (i = 0; i < afl->fsrv.map_size; ++i) {
      if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))) &&
          afl->top_rated[i]->trace_mini) {
        u32 j = len; 
        while (j--) {
          if (afl->top_rated[i]->trace_mini[j]) { 
            temp_v[j] &= ~afl->top_rated[i]->trace_mini[j]; 
          }
        }
        if (!afl->top_rated[i]->favored) {
          afl->top_rated[i]->favored = 1; 
          ++afl->queued_favored;          
          if (!afl->top_rated[i]->was_fuzzed) { 
            ++afl->pending_favored; 
            if (unlikely(afl->smallest_favored < 0) || afl->top_rated[i]->id < (u32)afl->smallest_favored) {
               afl->smallest_favored = (s64)afl->top_rated[i]->id; 
            }
          }
        }
      }
    }

    for (i = 0; i < afl->queued_items; i++) {
      if (afl->queue_buf[i] && likely(!afl->queue_buf[i]->disabled)) {
        mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);
      }
    }
    afl->reinit_table = 1; 
  }
}

// void cull_queue(afl_state_t *afl) {

//   // If score_changed is not set (meaning no new paths found recently by anyone)
//   // or if in non_instrumented_mode, the original culling logic might skip.
//   // We can decide if state-based culling should run regardless or also depend on this.
//   // For now, let's make the choice between strategies primary.

//   if (rand_below(afl, 100) < STATE_BASED_CULLING_PROB) {
//     /* --- New State-Based Favoring Logic --- */
//     ACTF("Attempting state-based queue culling.");

//     if (!afl->fsrv.state_info) {
//       WARNF("State-based culling skipped: state_info not initialized.");
//       return;
//     }

//     u32 top_states_count = 0;
//     // Define the percentage of top states to consider (e.g., 0.3% == 0.003)
//     double top_state_percentage = 0.003; // Consider making this configurable

//     // get_top_states should return a ck_alloc'd array of state_info_t*
//     state_info_t **top_states =
//         get_top_states(&afl->fsrv, top_state_percentage, &top_states_count);

//     // Debugging output (can be removed or put behind #ifdef DEBUG)
//     /*
//     FILE *sbfile = fopen("topstates_debug.txt","a");
//     if (sbfile) {
//         fprintf(sbfile,"State-based culling: Found %u top states (target percentage: %f)\n", top_states_count, top_state_percentage);
//         for(u32 i = 0; i < top_states_count; i++) {
//             if (top_states[i]) {
//                  fprintf(sbfile,"Top state ID: %u, score: %.10f, seed heap size: %u\n",
//                     top_states[i]->state_id,
//                     top_states[i]->total_score,
//                     top_states[i]->heap_size);
//                 if (top_states[i]->heap_size > 0) {
//                     fprintf(sbfile, "  Best seed for this state: ID %u, Score in state: %.10f\n",
//                         top_states[i]->top_seeds[0].queue_id, // Assuming queue_id field
//                         top_states[i]->top_seeds[0].score);
//                 }
//             }
//         }
//         fclose(sbfile);
//     }
//     */


//     // Reset favored status for all queue entries *before* applying new logic
//     for (u32 i = 0; i < afl->queued_items; i++) {
//       if (afl->queue_buf[i]) { afl->queue_buf[i]->favored = 0; }
//     }
//     afl->queued_favored = 0;  // Reset counter
//     afl->pending_favored = 0;
//     afl->smallest_favored = -1; // Reset smallest

//     if (!top_states || top_states_count == 0) {
//       WARNF("State-based culling: No top states found or allocation failed.");
//       if (top_states) ck_free(top_states); // Free if allocated but count is 0
//       // No changes to favoring, so no need to reinit table or mark redundant yet.
//       // Consider if we should fall back to original culling here.
//       // For now, if state-based culling is chosen but finds nothing, it does nothing.
//       return;
//     }

//     // Estimate max possible seeds to favor.
//     // If we take one best seed per top state.
//     u32 max_possible_favored_seeds = top_states_count;
//     u32 *favored_seed_ids = (u32 *)ck_alloc(sizeof(u32) * max_possible_favored_seeds);
//     // ck_alloc PFATALs on failure, no need to check favored_seed_ids for NULL

//     u32 actual_favored_count = 0;

//     // Collect the best seed(s) from each top state
//     for (u32 i = 0; i < top_states_count; i++) {
//       state_info_t *current_state = top_states[i];

//       // Check if the seed heap for this state has entries and current_state is valid
//       if (current_state && current_state->heap_size > 0) {
//         // Favor only the single best seed (root of the seed max-heap)
//         // Assuming seed_entry_t has 'queue_id' and 'score'
//         u32 best_seed_id = current_state->top_seeds[0].queue_id;

//         // Prevent adding duplicate seed IDs to our favored list
//         u8  already_added = 0;
//         for (u32 k = 0; k < actual_favored_count; ++k) {
//           if (favored_seed_ids[k] == best_seed_id) {
//             already_added = 1;
//             break;
//           }
//         }

//         if (!already_added && actual_favored_count < max_possible_favored_seeds) {
//           favored_seed_ids[actual_favored_count++] = best_seed_id;
//         }
//       }
//     }
//     ck_free(top_states);  // Free the array of pointers returned by get_top_states

//     // Mark the collected unique seeds as favored by iterating through the actual queue
//     for (u32 i = 0; i < actual_favored_count; i++) {
//       u32 target_id = favored_seed_ids[i];
//       struct queue_entry *q_found = NULL;

//       // Find the queue entry by ID
//       for (u32 queue_idx = 0; queue_idx < afl->queued_items; ++queue_idx) {
//         if (afl->queue_buf[queue_idx] &&
//             afl->queue_buf[queue_idx]->id == target_id) {
//           q_found = afl->queue_buf[queue_idx];
//           break;  // Found the entry
//         }
//       }

//       if (q_found) {
//         if (!q_found->favored && !q_found->disabled) { // Check if not already favored and not disabled
//           q_found->favored = 1;
//           afl->queued_favored++;
//           if (!q_found->was_fuzzed) {
//             ++afl->pending_favored;
//             if (unlikely(afl->smallest_favored < 0) ||
//                 q_found->id < (u32)afl->smallest_favored) {
//               afl->smallest_favored = (s64)q_found->id;
//             }
//           }
//         }
//       } else {
//          // WARNF("State-favored seed ID %u not found in current queue!", target_id);
//       }
//     }
//     ck_free(favored_seed_ids);  // Free the temporary ID array

//     // Mark entries not favored in this pass as redundant
//     for (u32 i = 0; i < afl->queued_items; i++) {
//       if (afl->queue_buf[i] && likely(!afl->queue_buf[i]->disabled)) {
//         mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);
//       }
//     }

//     if (actual_favored_count > 0 || afl->queued_favored > 0) { // If any changes to favored status
//         afl->score_changed = 1; // Indicate that scores/favored status changed
//     }
//     afl->reinit_table = 1;  // Signal alias table rebuild needed due to potential changes in favored status

//     OKF("State-based culling resulted in %u unique seeds favored.", actual_favored_count);

//   } else {
//     /* --- Original AFL++ Bitmap-Based Culling Logic --- */
//     ACTF("Attempting original bitmap-based queue culling.");

//     if (likely(!afl->score_changed || afl->non_instrumented_mode)) { return; }

//     u32 len = (afl->fsrv.map_size >> 3); // map_size is in bytes, len is in u64 blocks for trace_mini
//     u32 i;
//     u8 *temp_v = afl->map_tmp_buf; // Temporary buffer for bitmap operations

//     afl->score_changed = 0; // Reset flag, will be set if culling makes changes

//     memset(temp_v, 255, len); // Initialize temp_v to all 1s

//     afl->queued_favored = 0;  // Reset counters
//     afl->pending_favored = 0;

//     // Initially, mark all queue entries as not favored
//     for (i = 0; i < afl->queued_items; i++) {
//       if (afl->queue_buf[i]) { // Ensure entry exists
//           afl->queue_buf[i]->favored = 0;
//       }
//     }

//     /* Let's see if anything in the bitmap isn't captured in temp_v.
//        If yes, and if it has a afl->top_rated[] contender, let's use it. */
//     afl->smallest_favored = -1; // Reset smallest favored ID

//     for (i = 0; i < afl->fsrv.map_size; ++i) {
//       // If there's a top-rated seed for this bit, and this bit is still set in temp_v,
//       // and the seed has a minimized trace (trace_mini)
//       if (afl->top_rated[i] && (temp_v[i >> 3] & (1 << (i & 7))) &&
//           afl->top_rated[i]->trace_mini) {

//         u32 j = len; // Number of u64 blocks in trace_mini

//         /* Remove all bits belonging to the current top_rated[i] entry from temp_v. */
//         while (j--) {
//           if (afl->top_rated[i]->trace_mini[j]) { // If this block of trace_mini has bits
//             temp_v[j] &= ~afl->top_rated[i]->trace_mini[j]; // Clear these bits in temp_v
//           }
//         }

//         // If this seed wasn't already marked favored in this culling pass
//         if (!afl->top_rated[i]->favored) {
//           afl->top_rated[i]->favored = 1; // Mark as favored
//           ++afl->queued_favored;          // Increment count of favored seeds

//           if (!afl->top_rated[i]->was_fuzzed) { // If it hasn't been fuzzed yet
//             ++afl->pending_favored; // Increment count of pending favored seeds
//             if (unlikely(afl->smallest_favored < 0) || afl->top_rated[i]->id < (u32)afl->smallest_favored) {
//                afl->smallest_favored = (s64)afl->top_rated[i]->id; // Update smallest favored ID
//             }
//           }
//         }
//       }
//     }

//     // Mark entries not favored in this pass as redundant
//     for (i = 0; i < afl->queued_items; i++) {
//       if (afl->queue_buf[i] && likely(!afl->queue_buf[i]->disabled)) {
//         mark_as_redundant(afl, afl->queue_buf[i], !afl->queue_buf[i]->favored);
//       }
//     }
//     afl->reinit_table = 1; // Signal that the alias table needs rebuilding
//   }
// }

/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

u32 calculate_score(afl_state_t *afl, struct queue_entry *q) {

  u32 cal_cycles = afl->total_cal_cycles;
  u32 bitmap_entries = afl->total_bitmap_entries;

  if (unlikely(!cal_cycles)) { cal_cycles = 1; }
  if (unlikely(!bitmap_entries)) { bitmap_entries = 1; }

  u32 avg_exec_us = afl->total_cal_us / cal_cycles;
  u32 avg_bitmap_size = afl->total_bitmap_size / bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (likely(afl->schedule < RARE) && likely(!afl->fixed_seed)) {

    if (q->exec_us * 0.1 > avg_exec_us) {

      perf_score = 10;

    } else if (q->exec_us * 0.25 > avg_exec_us) {

      perf_score = 25;

    } else if (q->exec_us * 0.5 > avg_exec_us) {

      perf_score = 50;

    } else if (q->exec_us * 0.75 > avg_exec_us) {

      perf_score = 75;

    } else if (q->exec_us * 4 < avg_exec_us) {

      perf_score = 300;

    } else if (q->exec_us * 3 < avg_exec_us) {

      perf_score = 200;

    } else if (q->exec_us * 2 < avg_exec_us) {

      perf_score = 150;

    }

  }

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) {

    perf_score *= 3;

  } else if (q->bitmap_size * 0.5 > avg_bitmap_size) {

    perf_score *= 2;

  } else if (q->bitmap_size * 0.75 > avg_bitmap_size) {

    perf_score *= 1.5;

  } else if (q->bitmap_size * 3 < avg_bitmap_size) {

    perf_score *= 0.25;

  } else if (q->bitmap_size * 2 < avg_bitmap_size) {

    perf_score *= 0.5;

  } else if (q->bitmap_size * 1.5 < avg_bitmap_size) {

    perf_score *= 0.75;

  }

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    --q->handicap;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;

  }

  u32         n_items;
  double      factor = 1.0;
  long double fuzz_mu;

  switch (afl->schedule) {

    case EXPLORE:
      break;

    case SEEK:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_mu = 0.0;
      n_items = 0;

      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      u32 i;
      for (i = 0; i < afl->queued_items; i++) {

        if (likely(!afl->queue_buf[i]->disabled)) {

          fuzz_mu += log2(afl->n_fuzz[afl->queue_buf[i]->n_fuzz_entry]);
          n_items++;

        }

      }

      if (unlikely(!n_items)) { FATAL("Queue state corrupt"); }

      fuzz_mu = fuzz_mu / n_items;

      if (log2(afl->n_fuzz[q->n_fuzz_entry]) > fuzz_mu) {

        /* Never skip favourites */
        if (!q->favored) factor = 0;

        break;

      }

    // Fall through
    case FAST:

      // Don't modify unfuzzed seeds
      if (!q->fuzz_level) break;

      switch ((u32)log2(afl->n_fuzz[q->n_fuzz_entry])) {

        case 0 ... 1:
          factor = 4;
          break;

        case 2 ... 3:
          factor = 3;
          break;

        case 4:
          factor = 2;
          break;

        case 5:
          break;

        case 6:
          if (!q->favored) factor = 0.8;
          break;

        case 7:
          if (!q->favored) factor = 0.6;
          break;

        default:
          if (!q->favored) factor = 0.4;
          break;

      }

      if (q->favored) factor *= 1.15;

      break;

    case LIN:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor = q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case QUAD:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor =
          q->fuzz_level * q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case MMOPT:
      /* -- this was a more complex setup, which is good, but competed with
         -- rare. the simpler algo however is good when rare is not.
        // the newer the entry, the higher the pref_score
        perf_score *= (1 + (double)((double)q->depth /
        (double)afl->queued_items));
        // with special focus on the last 8 entries
        if (afl->max_depth - q->depth < 8) perf_score *= (1 + ((8 -
        (afl->max_depth - q->depth)) / 5));
      */
      // put focus on the last 5 entries
      if (afl->max_depth - q->depth < 5) { perf_score *= 2; }

      break;

    case RARE:

      // increase the score for every bitmap byte for which this entry
      // is the top contender
      perf_score += (q->tc_ref * 10);
      // the more often fuzz result paths are equal to this queue entry,
      // reduce its value
      perf_score *= (1 - (double)((double)afl->n_fuzz[q->n_fuzz_entry] /
                                  (double)afl->fsrv.total_execs));

      break;

    default:
      PFATAL("Unknown Power Schedule");

  }

  if (unlikely(afl->schedule >= EXPLOIT && afl->schedule <= QUAD)) {

    if (factor > MAX_FACTOR) { factor = MAX_FACTOR; }
    perf_score *= factor / POWER_BETA;

  }

  // MOpt mode
  if (afl->limit_time_sig != 0 && afl->max_depth - q->depth < 3) {

    perf_score *= 2;

  } else if (afl->schedule != COE && perf_score < 1) {

    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  }

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100) {

    perf_score = afl->havoc_max_mult * 100;

  }

  return perf_score;

}

/* after a custom trim we need to reload the testcase from disk */

inline void queue_testcase_retake(afl_state_t *afl, struct queue_entry *q,
                                  u32 old_len) {

  if (likely(q->testcase_buf)) {

    u32 len = q->len;

    // only realloc if necessary or useful
    // (a custom trim can make the testcase larger)
    if (unlikely(len > old_len || len < old_len + 1024)) {

      afl->q_testcase_cache_size += len - old_len;
      q->testcase_buf = (u8 *)realloc(q->testcase_buf, len);

      if (unlikely(!q->testcase_buf)) {

        PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

      }

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, q->testcase_buf, len, q->fname);
    close(fd);

  }

}

/* after a normal trim we need to replace the testcase with the new data */

inline void queue_testcase_retake_mem(afl_state_t *afl, struct queue_entry *q,
                                      u8 *in, u32 len, u32 old_len) {

  if (likely(q->testcase_buf)) {

    if (likely(in != q->testcase_buf)) {

      // only realloc if we save memory
      if (unlikely(len < old_len + 1024)) {

        u8 *ptr = (u8 *)realloc(q->testcase_buf, len);

        if (likely(ptr)) {

          q->testcase_buf = ptr;
          afl->q_testcase_cache_size += len - old_len;

        }

      }

      memcpy(q->testcase_buf, in, len);

    }

  }

}

/* Returns the testcase buf from the file behind this queue entry.
   Increases the refcount. */

inline u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  if (likely(q->testcase_buf)) { return q->testcase_buf; }

  u32    len = q->len;
  double weight = q->weight;

  // first handle if no testcase cache is configured, or if the
  // weighting of the testcase is below average.

  if (unlikely(weight < 1.0 || !afl->q_testcase_max_cache_size)) {

    u8 *buf;

    if (likely(q == afl->queue_cur)) {

      buf = (u8 *)afl_realloc((void **)&afl->testcase_buf, len);

    } else {

      buf = (u8 *)afl_realloc((void **)&afl->splicecase_buf, len);

    }

    if (unlikely(!buf)) {

      PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

    }

    int fd = open((char *)q->fname, O_RDONLY);

    if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

    ck_read(fd, buf, len, q->fname);
    close(fd);
    return buf;

  }

  /* now handle the testcase cache and we know it is an interesting one */

  /* Buf not cached, let's load it */
  u32        tid = afl->q_testcase_max_cache_count;
  static u32 do_once = 0;  // because even threaded we would want this. WIP

  while (unlikely(
      (afl->q_testcase_cache_size + len >= afl->q_testcase_max_cache_size &&
       afl->q_testcase_cache_count > 1) ||
      afl->q_testcase_cache_count >= afl->q_testcase_max_cache_entries - 1)) {

    /* We want a max number of entries to the cache that we learn.
       Very simple: once the cache is filled by size - that is the max. */

    if (unlikely(
            afl->q_testcase_cache_size + len >=
                afl->q_testcase_max_cache_size &&
            (afl->q_testcase_cache_count < afl->q_testcase_max_cache_entries &&
             afl->q_testcase_max_cache_count <
                 afl->q_testcase_max_cache_entries) &&
            !do_once)) {

      if (afl->q_testcase_max_cache_count > afl->q_testcase_cache_count) {

        afl->q_testcase_max_cache_entries = afl->q_testcase_max_cache_count + 1;

      } else {

        afl->q_testcase_max_cache_entries = afl->q_testcase_cache_count + 1;

      }

      do_once = 1;
      // release unneeded memory
      afl->q_testcase_cache = (struct queue_entry **)ck_realloc(
          afl->q_testcase_cache,
          (afl->q_testcase_max_cache_entries + 1) * sizeof(size_t));

    }

    /* Cache full. We need to evict one or more to map one.
       Get a random one which is not in use */

    do {

      // if the cache (MB) is not enough for the queue then this gets
      // undesirable because q_testcase_max_cache_count grows sometimes
      // although the number of items in the cache will not change hence
      // more and more loops
      tid = rand_below(afl, afl->q_testcase_max_cache_count);

    } while (afl->q_testcase_cache[tid] == NULL ||

             afl->q_testcase_cache[tid] == afl->queue_cur);

    struct queue_entry *old_cached = afl->q_testcase_cache[tid];
    free(old_cached->testcase_buf);
    old_cached->testcase_buf = NULL;
    afl->q_testcase_cache_size -= old_cached->len;
    afl->q_testcase_cache[tid] = NULL;
    --afl->q_testcase_cache_count;
    ++afl->q_testcase_evictions;
    if (tid < afl->q_testcase_smallest_free)
      afl->q_testcase_smallest_free = tid;

  }

  if (unlikely(tid >= afl->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = afl->q_testcase_smallest_free;

  }

  // we need this while loop in case there were ever previous evictions but
  // not in this call.
  while (unlikely(afl->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  int fd = open((char *)q->fname, O_RDONLY);

  if (unlikely(fd < 0)) { PFATAL("Unable to open '%s'", (char *)q->fname); }

  q->testcase_buf = (u8 *)malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  ck_read(fd, q->testcase_buf, len, q->fname);
  close(fd);

  /* Register testcase as cached */
  afl->q_testcase_cache[tid] = q;
  afl->q_testcase_cache_size += len;
  ++afl->q_testcase_cache_count;
  if (likely(tid >= afl->q_testcase_max_cache_count)) {

    afl->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

    afl->q_testcase_smallest_free = tid + 1;

  }

  return q->testcase_buf;

}

/* Adds the new queue entry to the cache. */

inline void queue_testcase_store_mem(afl_state_t *afl, struct queue_entry *q,
                                     u8 *mem) {

  u32 len = q->len;

  if (unlikely(q->weight < 1.0 ||
               afl->q_testcase_cache_size + len >=
                   afl->q_testcase_max_cache_size ||
               afl->q_testcase_cache_count >=
                   afl->q_testcase_max_cache_entries - 1)) {

    // no space or uninteresting? will be loaded regularly later.
    return;

  }

  u32 tid;

  if (unlikely(afl->q_testcase_max_cache_count >=
               afl->q_testcase_max_cache_entries)) {

    // uh we were full, so now we have to search from start
    tid = afl->q_testcase_smallest_free;

  } else {

    tid = afl->q_testcase_max_cache_count;

  }

  while (unlikely(afl->q_testcase_cache[tid] != NULL))
    ++tid;

  /* Map the test case into memory. */

  q->testcase_buf = (u8 *)malloc(len);

  if (unlikely(!q->testcase_buf)) {

    PFATAL("Unable to malloc '%s' with len %u", (char *)q->fname, len);

  }

  memcpy(q->testcase_buf, mem, len);

  /* Register testcase as cached */
  afl->q_testcase_cache[tid] = q;
  afl->q_testcase_cache_size += len;
  ++afl->q_testcase_cache_count;

  if (likely(tid >= afl->q_testcase_max_cache_count)) {

    afl->q_testcase_max_cache_count = tid + 1;

  } else if (unlikely(tid == afl->q_testcase_smallest_free)) {

    afl->q_testcase_smallest_free = tid + 1;

  }

}

