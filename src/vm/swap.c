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
    PANIC("No swap block device found");
  }

  size_t swap_size = block_size(swap_block) / (PGSIZE / BLOCK_SECTOR_SIZE);
  swap_bitmap = bitmap_create(swap_size);

  if (swap_bitmap == NULL) {
    PANIC("Couldn't create swap bitmap");
  }
  
  lock_init(&swap_lock);
}