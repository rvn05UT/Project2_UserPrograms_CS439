#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdbool.h>
#include <list.h>
#include "threads/synch.h"
#include "threads/thread.h"

/* A physical user frame tracked in the global frame table. */
struct frame {
  void *kpage;               /* Kernel virtual address of the frame. */
  void *upage;               /* User virtual page mapped to this frame. */
  struct thread *owner;      /* Owning thread (process). */
  bool pinned;               /* Pinned frames are not evictable. */
  struct list_elem elem;     /* List linkage in global frame list. */
};

//initialize global frame table
void frame_table_init(void);

//allocate a frame and its user page
void *frame_alloc(void *upage, bool writable, bool zero);

//free frame and its page
void frame_free(void *kpage);

//remove all the frame metadata owned by current process
void frame_remove_owner(struct thread *t);

//pin/unpin helpers
void frame_pin(void *kpage);
void frame_unpin(void *kpage);

// evict a frame and return its kpage
void *frame_evict(void);

#endif 
