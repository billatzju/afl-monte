#include "uthash.h"
#include "forkserver.h"

#ifndef __AFL_HASH_H
#define __AFL_HASH_H

void state_map_init(afl_forkserver_t *fsrv);
void state_map_destroy(afl_forkserver_t *fsrv);
u8 state_map_lookup(afl_forkserver_t *fsrv, u32 state_id, u32 *heap_index_ptr);
u8 state_map_upsert(afl_forkserver_t *fsrv, u32 state_id, u32 new_heap_index);
u8 state_map_delete(afl_forkserver_t *fsrv, u32 state_id);

#endif