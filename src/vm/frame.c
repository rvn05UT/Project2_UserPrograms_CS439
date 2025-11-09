#include "vm/frame.h"
#include <debug.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

//global frame table
static struct list frame_list;
static struct lock frame_lock;
static struct list_elem *clock_hand;

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
  if (kpage == NULL) {
    frame_evict();
  }
   

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
  struct page *p = NULL;

  if (clock_hand == NULL || clock_hand == list_end(&frame_list)) {
    lock_acquire(&frame_lock);
    clock_hand = list_begin(&frame_list);
    lock_release(&frame_lock);
  }

  struct frame *victim = NULL;
  int counter = 0;
  bool first_pass = true;

  lock_acquire(&frame_lock);
  while (counter < list_size(&frame_list) * 2) {
    //ensure we set second pass
    if(counter == list_size(&frame_list)) {
      first_pass = false;
    }
    struct frame *fr = list_entry(clock_hand, struct frame, elem);

    if (!fr->pinned) {
      // if its not accessed, we reset to accessed and check conditions for eviction
      if (!pagedir_is_accessed(fr->owner->pagedir, fr->upage) && !pagedir_is_accessed(fr->owner->pagedir, fr->kpage)) {

        pagedir_set_accessed(fr->owner->pagedir, fr->upage, true);
        pagedir_set_accessed(fr->owner->pagedir, fr->kpage, true);
        //if its not dirty then we just set victim, if its the second pass then we have to set the victim
        if(!first_pass || (!pagedir_is_dirty(fr->owner->pagedir, fr->upage) && !pagedir_is_dirty(fr->owner->pagedir, fr->upage))) {
          victim = fr;
          clock_hand = list_next(clock_hand);
          if (clock_hand == list_end(&frame_list)) {
            clock_hand = list_begin(&frame_list);
          }
          break;
        }
      }
      // if it is accessed then we clear accessed
      else {
        pagedir_set_accessed(fr->owner->pagedir, fr->upage, false);
        pagedir_set_accessed(fr->owner->pagedir, fr->kpage, false);
      }
    }
    
    clock_hand = list_next(clock_hand);
    if (clock_hand == list_end(&frame_list)) {
      clock_hand = list_begin(&frame_list);
    }
    counter++;
  }
  lock_release(&frame_lock);

  struct page* evicted_page = page_lookup(&thread_current()->spt, victim->upage);
  lock_acquire(&frame_lock);

  //if its dirty we need swap out 
  if(pagedir_is_dirty(victim->owner->pagedir, victim->upage) || pagedir_is_dirty(victim->owner->pagedir, victim->kpage)) {
    evicted_page->type = PAGE_SWAP; 
    evicted_page -> page_slot = swap_out(victim->kpage);
  }
  frame_free(victim->kpage);
  lock_release(&frame_lock);
}