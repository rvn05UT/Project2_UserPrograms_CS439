#include "vm/page.h"
#include <debug.h>
#include <string.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"

static void page_destructor(struct hash_elem *e, void *aux UNUSED) {
    struct page *p = hash_entry(e, struct page, elem);
    free(p);
}


//initalize the SPT
void page_table_init(struct hash *spt) {
    hash_init(spt, page_hash, page_less, NULL);
}
//destroy the SPT
void page_table_destroy(struct hash *spt) {
    hash_destroy(spt, page_destructor);
}

//create a file backed page entry
struct page * page_create_file (void *upage, struct file *file, off_t offset,
                  uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  struct page *p = malloc (sizeof *p);
  if (p == NULL)
    return NULL;
  
  p->upage = pg_round_down (upage);
  p->type = PAGE_FILE;
  p->writable = writable;
  p->loaded = false;
  p->file = file;
  p->file_ofs = offset;
  p->read_bytes = read_bytes;
  p->zero_bytes = zero_bytes;
  
  return p;
}

//create a zero filled page entry
struct page *
page_create_zero (void *upage)
{
  struct page *p = malloc (sizeof *p);
  if (p == NULL)
    return NULL;
  
  p->upage = pg_round_down (upage);
  p->type = PAGE_ZERO;
  p->writable = true;
  p->loaded = false;
  p->file = NULL;
  p->file_ofs = 0;
  p->read_bytes = 0;
  p->zero_bytes = PGSIZE;
  
  return p;
}

//find a page in the SPT using our virtual address
struct page *
page_lookup (struct hash *spt, void *upage)
{
  struct page p;
  struct hash_elem *e;
  
  p.upage = pg_round_down (upage);
  e = hash_find (spt, &p.elem);
  
  return e != NULL ? hash_entry (e, struct page, elem) : NULL;
}


//install a page into our SPT
bool page_install (struct hash *spt, struct page *p)
{
  return hash_insert (spt, &p->elem) == NULL;
}

//remove the page at the given virtual address from our SPT
void page_remove (struct hash *spt, void *upage)
{
  struct page *p = page_lookup (spt, upage);
  if (p != NULL)
    {
      hash_delete (spt, &p->elem);
      free (p);
    }
}

//set whether the page is loaded into memory or not
void page_set_loaded (struct page *p, bool loaded)
{
  if (p != NULL)
    p->loaded = loaded;
}

//hash function for our page table
unsigned page_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct page *p = hash_entry (e, struct page, elem);
  return hash_int ((int) p->upage);
}

//comparison function for our page table
bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct page *pa = hash_entry (a, struct page, elem);
  const struct page *pb = hash_entry (b, struct page, elem);
  
  return pa->upage < pb->upage;
}