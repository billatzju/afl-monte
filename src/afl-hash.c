#include "afl-hash.h"
#include "alloc-inl.h"
// --- UTHash Wrapper Functions ---

/**
 * @brief Initializes the state ID -> heap index map (sets head to NULL).
 */
void state_map_init(afl_forkserver_t *fsrv) {
    fsrv->state_id_to_index_map = NULL; // Essential for uthash
    ACTF("Initialized uthash state_map (head=NULL)");
}

/**
 * @brief Destroys the state map, freeing all allocated entries.
 */
void state_map_destroy(afl_forkserver_t *fsrv) {
    state_index_map_entry_t *current_entry, *tmp;

    HASH_ITER(hh, fsrv->state_id_to_index_map, current_entry, tmp) {
        HASH_DEL(fsrv->state_id_to_index_map, current_entry);
        ck_free(current_entry);
    }
    fsrv->state_id_to_index_map = NULL;
}

/**
 * @brief Looks up the heap_index for a given state_id using uthash.
 * Returns 1 and sets *heap_index_ptr if found, 0 otherwise.
 */
u8 state_map_lookup(afl_forkserver_t *fsrv, u32 state_id, u32 *heap_index_ptr) {

    state_index_map_entry_t * found_entry1;
    HASH_FIND_INT(fsrv->state_id_to_index_map, &state_id, found_entry1);
    

    // state_index_map_entry_t *found_entry =(state_index_map_entry_t *)ck_alloc(sizeof(state_index_map_entry_t));
    // // NOTE: For HASH_FIND_INT, the key MUST be the address of the key field
    // // within a struct of the same type, or the address of a standalone variable.
    // // Using a pointer to a struct containing the key is standard.
    
    // key_struct.state_id = state_id;
    
    // HASH_FIND_INT(fsrv->state_id_to_index_map, &state_id, found_entry);
    // //printf("found index:%d",found_entry->heap_index);

    if (found_entry1) {
        // FILE *score_rec = fopen("score_records","a");
        // fprintf(score_rec,"found the state %d in the heap index: %d\n",state_id, found_entry1->heap_index);
        // fclose(score_rec);
        //printf("found\n");
        if (heap_index_ptr) *heap_index_ptr = found_entry1->heap_index;

        //printf("found index:%d",found_entry->heap_index);
        return 1; // Found
    }
    //printf("not found %d\n", state_id);
    return 0; // Not found
}

/**
 * @brief Inserts or updates the heap_index for a given state_id using uthash.
 * Returns 1 on success, 0 on allocation failure.
 */
u8 state_map_upsert(afl_forkserver_t *fsrv, u32 state_id, u32 new_heap_index) {
    state_index_map_entry_t *found_entry;

    HASH_FIND_INT(fsrv->state_id_to_index_map, &state_id,  found_entry);

    if (found_entry) {
        found_entry->heap_index = new_heap_index; // Update existing
    } else {
        found_entry = (state_index_map_entry_t *)ck_alloc(sizeof(state_index_map_entry_t));
        if (!found_entry) {
             WARNF("Failed to allocate new entry for uthash state_map_upsert");
             return 0;
        }
        found_entry->state_id = state_id;
        found_entry->heap_index = new_heap_index;
        HASH_ADD_INT(fsrv->state_id_to_index_map, state_id, found_entry); // Add key field name
    }
    // state_index_map_entry_t * found_entry1 = (state_index_map_entry_t *)ck_alloc(sizeof(state_index_map_entry_t));
    // HASH_FIND_INT(fsrv->state_id_to_index_map, &state_id, found_entry1);
    // if (found_entry1){
    //     printf("attempt to find immediately after adding key,value pair%d,%d\n", state_id,found_entry1->heap_index);
    // }
    return 1;
}

/**
 * @brief Deletes the entry for a given state_id using uthash (Optional).
 * Returns 1 if deleted, 0 if not found.
 */
u8 state_map_delete(afl_forkserver_t *fsrv, u32 state_id) {
    state_index_map_entry_t *found_entry;
    state_index_map_entry_t key_struct;
    key_struct.state_id = state_id;

    HASH_FIND(hh, fsrv->state_id_to_index_map, &key_struct.state_id, sizeof(u32), found_entry);

    if (found_entry) {
        HASH_DEL(fsrv->state_id_to_index_map, found_entry);
        ck_free(found_entry);
        return 1;
    }
    return 0;
}