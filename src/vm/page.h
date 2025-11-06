#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stdint.h>
#include "filesys/file.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"

enum type_of_page {
    PAGE_FILE, //page backed by an executable segment
    PAGE_ZERO, //page zero filled 
};

struct page {
    void *upage; //user virutal address
    enum type_of_page type; //what type of page this is 
    bool writable; //whether we can write to the page or not
    bool loaded; // whether the page is loaded into memory
    struct hash_elem elem; //hash table element

    struct file *file; //file contianing the page data
    off_t file_ofs; //offset in f

    uint32_t read_bytes; //bytes to read from file
    uint32_t zero_bytes; //bytes to zero-fill

};

void page_table_init(struct hash *spt);
void page_table_destroy(struct hash *spt);
struct page *page_lookup(struct hash *spt, void *upage);
struct page *page_create_file (void *upage, struct file *file, off_t offset,
    uint32_t read_bytes, uint32_t zero_bytes, bool writable);
struct page *page_create_zero(void *upage);
bool page_install (struct hash *spt, struct page *p);
void page_remove (struct hash *spt, void *upage);
void page_set_loaded (struct page *p, bool loaded);
unsigned page_hash (const struct hash_elem *e, void *aux);
bool page_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);

#endif
