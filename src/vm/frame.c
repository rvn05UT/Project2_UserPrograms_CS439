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

// void *frame_alloc(void *upage, bool writable, bool zero)
// {
//   (void)writable; /* reserved for future policies */

//   enum palloc_flags flags = PAL_USER | (zero ? PAL_ZERO : 0);
//   void *kpage = palloc_get_page(flags);
//   if (kpage == NULL) {
//     frame_evict();
//   }
   

//   struct frame *fr = malloc(sizeof *fr);
//   if (fr == NULL)
//     {
//       palloc_free_page(kpage);
//       return NULL;
//     }
//   fr->kpage = kpage;
//   fr->upage = upage;
//   fr->owner = thread_current();
//   fr->pinned = false;

//   lock_acquire(&frame_lock);
//   list_push_back(&frame_list, &fr->elem);

//   lock_release(&frame_lock);

//   return kpage;
// }

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
          /* If clock_hand points to this frame, advance it to the next element */
          if (clock_hand == e)
            {
              clock_hand = next;
              /* If we removed the last element, reset clock_hand */
              if (clock_hand == list_end(&frame_list))
                clock_hand = list_begin(&frame_list);
            }
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

// void *frame_evict(void)
// {
//   struct page *p = NULL;

//   if (clock_hand == NULL || clock_hand == list_end(&frame_list)) {
//     lock_acquire(&frame_lock);
//     clock_hand = list_begin(&frame_list);
//     lock_release(&frame_lock);
//   }

//   struct frame *victim = NULL;
//   int counter = 0;
//   bool first_pass = true;

//   lock_acquire(&frame_lock);
//   while (counter < list_size(&frame_list) * 2) {
//     //ensure we set second pass
//     if(counter == list_size(&frame_list)) {
//       first_pass = false;
//     }
//     struct frame *fr = list_entry(clock_hand, struct frame, elem);

//     if (!fr->pinned) {
//       // if its not accessed, we reset to accessed and check conditions for eviction
//       if (!pagedir_is_accessed(fr->owner->pagedir, fr->upage) && !pagedir_is_accessed(fr->owner->pagedir, fr->kpage)) {

//         pagedir_set_accessed(fr->owner->pagedir, fr->upage, true);
//         pagedir_set_accessed(fr->owner->pagedir, fr->kpage, true);
//         //if its not dirty then we just set victim, if its the second pass then we have to set the victim
//         if(!first_pass || (!pagedir_is_dirty(fr->owner->pagedir, fr->upage) && !pagedir_is_dirty(fr->owner->pagedir, fr->upage))) {
//           victim = fr;
//           clock_hand = list_next(clock_hand);
//           if (clock_hand == list_end(&frame_list)) {
//             clock_hand = list_begin(&frame_list);
//           }
//           break;
//         }
//       }
//       // if it is accessed then we clear accessed
//       else {
//         pagedir_set_accessed(fr->owner->pagedir, fr->upage, false);
//         pagedir_set_accessed(fr->owner->pagedir, fr->kpage, false);
//       }
//     }
    
//     clock_hand = list_next(clock_hand);
//     if (clock_hand == list_end(&frame_list)) {
//       clock_hand = list_begin(&frame_list);
//     }
//     counter++;
//   }
//   lock_release(&frame_lock);

//   struct page* evicted_page = page_lookup(&thread_current()->spt, victim->upage);
//   lock_acquire(&frame_lock);

//   //if its dirty we need swap out 
//   if(pagedir_is_dirty(victim->owner->pagedir, victim->upage) || pagedir_is_dirty(victim->owner->pagedir, victim->kpage)) {
//     evicted_page->type = PAGE_SWAP; 
//     evicted_page -> page_slot = swap_out(victim->kpage);
//   }
//   frame_free(victim->kpage);
//   lock_release(&frame_lock);
// }


/* In vm/frame.c */

void *frame_alloc(void *upage, bool writable, bool zero)
{
  (void)writable; /* Not used in this implementation */

  enum palloc_flags flags = PAL_USER | (zero ? PAL_ZERO : 0);
  void *kpage = palloc_get_page(flags);

  if (kpage == NULL) 
  {
    /* --- EVICTION TRIGGER --- */
    /* We are out of free frames. Evict one. */
    kpage = frame_evict(); 
    
    if (kpage == NULL) {
      /* Eviction failed (e.g., swap is full). */
      PANIC("VM: Eviction failed, out of memory and swap!");
    }

    /* If the original request wanted a zeroed page, we must
       zero the newly-evicted (and possibly dirty) frame. */
    if (zero) {
        memset(kpage, 0, PGSIZE);
    }
  }

  /* Now that we have a valid kpage, track its metadata */
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


void *frame_evict(void)
{
  lock_acquire(&frame_lock);

  /* Initialize clock hand if this is the first eviction */
  if (clock_hand == NULL || clock_hand == list_end(&frame_list)) {
    clock_hand = list_begin(&frame_list);
  }

  struct frame *victim = NULL;

  /* Clock algorithm: Loop until we find a victim */
  while (true) 
  {
    /* Wrap around the list if we reach the end */
    if (clock_hand == list_end(&frame_list)) {
        clock_hand = list_begin(&frame_list);
    }
    
    /* If the list is empty (shouldn't happen if we're evicting) */
    if (list_empty(&frame_list)) {
        lock_release(&frame_lock);
        return NULL; /* Or PANIC */
    }

    struct frame *fr = list_entry(clock_hand, struct frame, elem);
    /* Save next element before we potentially remove 'fr' */
    struct list_elem *next_hand = list_next(clock_hand); 

    if (!fr->pinned) 
    {
      /* Check if owner's page directory is still valid */
      if (fr->owner == NULL || fr->owner->pagedir == NULL) {
        /* Owner has exited - this frame can be evicted immediately */
        victim = fr;
        list_remove(&victim->elem);
        clock_hand = next_hand;
        break;
      }
      
      /* Check the accessed bit of the user page */
      if (pagedir_is_accessed(fr->owner->pagedir, fr->upage)) 
      {
        /* Give it a second chance: clear the accessed bit */
        pagedir_set_accessed(fr->owner->pagedir, fr->upage, false);
      } 
      else 
      {
        /* Not accessed: this is our victim. */
        victim = fr;
        list_remove(&victim->elem); // Remove from frame table
        clock_hand = next_hand;     // Advance clock hand
        break; 
      }
    }
    
    clock_hand = next_hand;
  }
  
  lock_release(&frame_lock);
  
  /* We have a victim. Now process it (no lock needed). */
  
  /* Check if owner has exited (pagedir is NULL) - if so, just free the frame */
  if (victim->owner == NULL || victim->owner->pagedir == NULL) {
    void *kpage = victim->kpage;
    free(victim);
    return kpage;
  }
  
  /* Find its SPT entry (from the VICTIM'S owner) */
  struct page *p = page_lookup(&victim->owner->spt, victim->upage);
  if (p == NULL) {
    /* SPT might have been destroyed - just free the frame */
    void *kpage = victim->kpage;
    free(victim);
    return kpage;
  }

  /* Check if dirty (must check both aliased addresses) */
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

  /* Update SPT: Mark as no longer loaded */
  page_set_loaded(p, false);

  /* Unmap from hardware pagedir */
  if (victim->owner != NULL && victim->owner->pagedir != NULL) {
    pagedir_clear_page(victim->owner->pagedir, victim->upage);
  }

  /* 6. Free the frame *metadata* (NOT the kpage) */
  void *kpage = victim->kpage;
  free(victim);

  /* 7. Return the freed kpage to frame_alloc */
  return kpage;

}

/* Pin all pages in a user buffer to avoid recursive page faults while holding FS locks. */
void vm_pin_buffer(const void *uaddr, size_t size, bool write_access)
{
  if (size == 0 || uaddr == NULL) return;
  struct thread *t = thread_current();
  uint8_t *start = (uint8_t *)uaddr;
  uint8_t *end = start + size - 1;
  for (uint8_t *p = pg_round_down(start); p <= pg_round_down(end); p += PGSIZE) {
    void *kpage = pagedir_get_page(t->pagedir, p);
    if (kpage == NULL) {
      /* Force a page fault to load the page. */
      volatile uint8_t tmp; /* Read triggers fault. */
      tmp = *(uint8_t *)p; (void)tmp;
      kpage = pagedir_get_page(t->pagedir, p);
      if (kpage == NULL)
        return; /* Failed; process will die elsewhere. */
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
  if (size == 0 || uaddr == NULL) return;
  struct thread *t = thread_current();
  uint8_t *start = (uint8_t *)uaddr;
  uint8_t *end = start + size - 1;
  for (uint8_t *p = pg_round_down(start); p <= pg_round_down(end); p += PGSIZE) {
    void *kpage = pagedir_get_page(t->pagedir, p);
    if (kpage != NULL)
      frame_unpin(kpage);
  }
}