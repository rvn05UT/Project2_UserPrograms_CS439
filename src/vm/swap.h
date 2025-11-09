#include <stddef.h>
#include "devices/block.h"

void swap_init(void);
void swap_free(size_t index);
size_t swap_out(void *kpage);
void swap_in(size_t index, void *kpage);