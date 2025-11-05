#include "vm/frame.h"
#include <debug.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

//global frame table
static struct list frame_list;
static struct lock frame_lock;

void frame_table_init(void)
{
  list_init(&frame_list);
  lock_init(&frame_lock);
}

/* Find frame struct by kpage. */
static struct frame *frame_find(void *kpage)
{
  struct list_elem *e;
  for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e))
    {
      struct frame *fr = list_entry(e, struct frame, elem);
      if (fr->kpage == kpage)
        return fr;
    }
  return NULL;
}

void *frame_alloc(void *upage, bool writable, bool zero)
{
  (void)writable; /* reserved for future policies */

  enum palloc_flags flags = PAL_USER | (zero ? PAL_ZERO : 0);
  void *kpage = palloc_get_page(flags);
  if (kpage == NULL)
    return NULL; /* TODO: implement eviction when no room */

  struct frame *fr = malloc(sizeof *fr);
  if (fr == NULL)
    {
      palloc_free_page(kpage);
      return NULL;
    }
  fr->kpage = kpage;
  fr->upage = upage;
  fr->owner = thread_current();
  fr->pinned = false;

  lock_acquire(&frame_lock);
  list_push_back(&frame_list, &fr->elem);
  lock_release(&frame_lock);

  return kpage;
}

void frame_free(void *kpage)
{
  if (kpage == NULL) return;
  lock_acquire(&frame_lock);
  struct frame *fr = frame_find(kpage);
  if (fr != NULL)
    {
      list_remove(&fr->elem);
      free(fr);
    }
  lock_release(&frame_lock);
  palloc_free_page(kpage);
}

void frame_remove_owner(struct thread *t)
{
  lock_acquire(&frame_lock);
  struct list_elem *e = list_begin(&frame_list);
  while (e != list_end(&frame_list))
    {
      struct frame *fr = list_entry(e, struct frame, elem);
      struct list_elem *next = list_next(e);
      if (fr->owner == t)
        {
          list_remove(e);
          /* Do not free kpage here; pagedir_destroy will free pages.
             We only drop tracking metadata to avoid dangling references. */
          free(fr);
        }
      e = next;
    }
  lock_release(&frame_lock);
}

void frame_pin(void *kpage)
{
  lock_acquire(&frame_lock);
  struct frame *fr = frame_find(kpage);
  if (fr) fr->pinned = true;
  lock_release(&frame_lock);
}

void frame_unpin(void *kpage)
{
  lock_acquire(&frame_lock);
  struct frame *fr = frame_find(kpage);
  if (fr) fr->pinned = false;
  lock_release(&frame_lock);
}

void *frame_evict(void)
{
  
  // // pick victim
  // struct frame *victim = NULL;
  // lock_acquire(&frame_lock);
  // struct list_elem *e;
  // for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e))
  //   {
  //     struct frame *fr = list_entry(e, struct frame, elem);
  //     if (!fr->pinned)
  //       {
  //         fr->pinned = true;
  //         victim = fr;
  //         break;
  //       }
  //   }
  // if (!victim) {
  //   lock_release(&frame_lock);
  //   return NULL; // no evictable frame found
  // }

  // // leave frame in list for now
  // void *kpage = victim->kpage;
  // struct thread *owner = victim->owner;
  // void *upage = victim->upage;
  // lock_release(&frame_lock);

  // // if still mapped, find where to save contents
  // if (owner != NULL && upage != NULL) {
  //   void *pagedir_entry = pagedir_get_page(owner->pagedir, upage);
  //   if (pagedir_entry != NULL) {
  //     struct page *p = page_lookup(owner, upage);

  //     if (pagedir_is_dirty(owner->pagedir, upage)) {
  //       int slot = swap_write(kpage);
  //       if (slot < 0) {
  //         lock_acquire(&frame_lock);
  //         struct frame *fr2 = frame_find(kpage);
  //         if (fr2) fr2->pinned = false;
  //         lock_release(&frame_lock);
  //         return NULL; // swap write failed
  //       }
  //     }
  //   }
  //   pagedir_clear_page(owner->pagedir, upage);
  // }

  // // remove frame from frame table and free it
  // lock_acquire(&frame_lock);
  //   struct frame *fr3 = frame_find(kpage);
  //   if (fr3) {
  //     list_remove(&fr3->elem);
  //     free(fr3);
  //   }
  //   lock_release(&frame_lock);

  //   if (kpage != NULL) {
  //     return kpage;
  //   }

  return NULL; // no evictable frame found
}
