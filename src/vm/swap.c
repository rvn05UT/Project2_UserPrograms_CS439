#include "vm/swap.h"
#include "threads/synch.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include <debug.h>

static struct block *swap_block;
static struct bitmap *swap_bitmap;
static struct lock swap_lock;

void swap_init(void) {
  swap_block = block_get_role(BLOCK_SWAP);
  if (swap_block == NULL) {
    PANIC("No swap block device found"); //panic the kernel
  }

  size_t swap_size = block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE);
  swap_bitmap = bitmap_create(swap_size);

  if (swap_bitmap == NULL) {
    PANIC("Couldn't create swap bitmap"); //panic the kernel
  }

  lock_init(&swap_lock);
}


size_t swap_out(void *kpage) {
  lock_acquire(&swap_lock);

  size_t slot = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  if (slot == BITMAP_ERROR) {
    // do I have to lock release here?
    PANIC("swap partiiton is full"); //panic the kernel
  }

  //write the page to the swap slot
  for (size_t i = 0; i < (PGSIZE / BLOCK_SECTOR_SIZE); i++) {
    block_write(swap_block, slot * (PGSIZE / BLOCK_SECTOR_SIZE) + i,
                (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
  }

  lock_release(&swap_lock);
  return slot;
}

void swap_in(size_t slot, void *kpage) {
  lock_acquire(&swap_lock);

  //read the page from the swap slot
  for (size_t i = 0; i < (PGSIZE / BLOCK_SECTOR_SIZE); i++) {
    block_read(swap_block, slot * (PGSIZE / BLOCK_SECTOR_SIZE) + i,
               (uint8_t *)kpage + i * BLOCK_SECTOR_SIZE);
  }

  //mark the swap slot as free
  bitmap_set(swap_bitmap, slot, false);

  lock_release(&swap_lock);
}

void swap_free(size_t slot) {
  lock_acquire(&swap_lock);
  bitmap_set(swap_bitmap, slot, false);
  lock_release(&swap_lock);
}