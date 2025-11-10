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
#include <string.h>
#include "threads/vaddr.h"

//global frame table
static struct list frame_list;
static struct lock frame_lock;
static struct list_elem *clock_hand;

void frame_table_init(void)
{
  list_init(&frame_list);
  lock_init(&frame_lock);
}

//find frame struct by kpage
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

//free the frame corresponding to the kpage
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

//remove owner metadata for a frame
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
          // ensure clock hand state
          if (clock_hand == e)
            {
              clock_hand = next;
              if (clock_hand == list_end(&frame_list)) {
                clock_hand = list_begin(&frame_list);
              }
            }
          list_remove(e);
          free(fr);
        }
      e = next;
    }

  lock_release(&frame_lock);
}

//pin a frame given by kpage
void frame_pin(void *kpage)
{
  lock_acquire(&frame_lock);
  struct frame *fr = frame_find(kpage);
  if (fr) fr->pinned = true;
  lock_release(&frame_lock);
}

//unpin a frame given by kpage
void frame_unpin(void *kpage)
{
  lock_acquire(&frame_lock);
  struct frame *fr = frame_find(kpage);
  if (fr) fr->pinned = false;
  lock_release(&frame_lock);
}


void *frame_alloc(void *upage, bool zero)
{
  if(upage == NULL) {
    return NULL;
  }

  enum palloc_flags flags = PAL_USER | (zero ? PAL_ZERO : 0);
  void *kpage = palloc_get_page(flags);

  if (kpage == NULL) 
  {
    // out of free frames, evict one
    kpage = frame_evict(); 
    
    //evict failure
    if (kpage == NULL) {
      // eviction failed (prob swap is full)
      PANIC("VM: Eviction failed, out of memory and swap!");
    }

    /* If the original request wanted a zeroed page,
       zero the newly-evicted (and possibly dirty) frame. */
    if (zero) {
        memset(kpage, 0, PGSIZE);
    }
  }

  // track valid kpage metadata
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

// evict a frame that is not pinned with clock algo on accessed and dirty bits
void *frame_evict(void)
{
  lock_acquire(&frame_lock);

  // ensure clock hand state
  if (clock_hand == NULL || clock_hand == list_end(&frame_list)) {
    clock_hand = list_begin(&frame_list);
  }

  // check for empty list
  if (list_empty(&frame_list)) {
      lock_release(&frame_lock);
      return NULL;
  }

  struct frame *victim = NULL;

  // clock algo
  while (true) 
  {
    //wrap around
    if (clock_hand == list_end(&frame_list)) {
        clock_hand = list_begin(&frame_list);
    }
    

    struct frame *fr = list_entry(clock_hand, struct frame, elem);
    // save next element before we potentially remove fr
    struct list_elem *next_hand = list_next(clock_hand);

    if (!fr->pinned) 
    {
      // check if owner's page directory is still valid 
      if (fr->owner == NULL || fr->owner->pagedir == NULL) {
        // owner exited, this frame can be evicted immediately
        victim = fr;
        list_remove(&victim->elem);
        clock_hand = next_hand;
        break;
      }
      
      // check and clear accessed bit
      if (pagedir_is_accessed(fr->owner->pagedir, fr->upage)) 
      {
        //c lear accessed bit
        pagedir_set_accessed(fr->owner->pagedir, fr->upage, false);
      } 
      else 
      {
        // not accessed, this is our victim
        victim = fr;
        list_remove(&victim->elem); // Remove from frame table
        clock_hand = next_hand;     // Advance clock hand
        break; 
      }
    }
    
    clock_hand = next_hand;
  }
  
  lock_release(&frame_lock);
  
  /* We have a victim, now process it */
  
  // check if owner has exited (pagedir is NULL) - if so, just free the frame 
  if (victim->owner == NULL || victim->owner->pagedir == NULL) {
    void *kpage = victim->kpage;
    free(victim);
    return kpage;
  }
  
  // find its SPT entry (from the VICTIM'S owner)
  struct page *p = page_lookup(&victim->owner->spt, victim->upage);
  if (p == NULL) {
    // SPT might have been destroyed - just free the frame
    void *kpage = victim->kpage;
    free(victim);
    return kpage;
  }

  // check if dirty (must check both aliased addresses)
  if (victim->owner == NULL || victim->owner->pagedir == NULL) {
    void *kpage = victim->kpage;
    free(victim);
    return kpage;
  }
  
  bool dirty = pagedir_is_dirty(victim->owner->pagedir, victim->upage) ||
               pagedir_is_dirty(victim->owner->pagedir, victim->kpage);

  /* If it's a clean file-backed page, we can just re-read from the file later.
     Otherwise (dirty file-backed, zero, or swap), write to swap. */
  if (!(p->type == PAGE_FILE && !dirty))
    {
      p->type = PAGE_SWAP;
      p->page_slot = swap_out(victim->kpage);
    }

  // update SPT, mark as no longer loaded
  page_set_loaded(p, false);

  // unmap from hardware pagedir
  if (victim->owner != NULL && victim->owner->pagedir != NULL) {
    pagedir_clear_page(victim->owner->pagedir, victim->upage);
  }

  // free victim metadata
  void *kpage = victim->kpage;
  free(victim);

  return kpage;

}

/* Pin all pages in a user buffer to avoid recursive page faults while holding FS locks. */
void vm_pin_buffer(const void *uaddr, size_t size, bool write_access)
{
  if (size == 0 || uaddr == NULL) {
    return;
  }

  struct thread *t = thread_current();
  uint8_t *start = (uint8_t *)uaddr;
  uint8_t *end = start + size - 1;

  for (uint8_t *p = pg_round_down(start); p <= pg_round_down(end); p += PGSIZE) {
    void *kpage = pagedir_get_page(t->pagedir, p);

    if (kpage == NULL) {
      // force a page fault to load the page.
      volatile uint8_t tmp; // read triggers fault
      tmp = *(uint8_t *)p; (void)tmp;
      kpage = pagedir_get_page(t->pagedir, p);
      if (kpage == NULL)
        return; // failed, process will die somehwere else
    }

    frame_pin(kpage);
    if (write_access) {
      pagedir_set_dirty(t->pagedir, p, true);
    }
  }
}

/* Unpin previously pinned buffer pages. */
void vm_unpin_buffer(const void *uaddr, size_t size)
{
  if (size == 0 || uaddr == NULL) {
    return;
  }

  struct thread *t = thread_current();
  uint8_t *start = (uint8_t *)uaddr;
  uint8_t *end = start + size - 1;

  for (uint8_t *p = pg_round_down(start); p <= pg_round_down(end); p += PGSIZE) {
    void *kpage = pagedir_get_page(t->pagedir, p);
    
    if (kpage != NULL)
      frame_unpin(kpage);
  }
}