#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
//#include <stdlib.h>
#include "threads/malloc.h"
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *file_name, void (**eip) (void), void **esp);

// External reference to the file system lock from syscall.c
extern struct lock filesys_lock;


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name)
{
  char *fn_copy;
  char *thread_name_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  // make a copy of just the program name for the thread name
  thread_name_copy = palloc_get_page (0);
  if (thread_name_copy == NULL) {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  strlcpy (thread_name_copy, fn_copy, PGSIZE);

  // extract program name for thread name
  char *save_ptr;
  char *thread_name = strtok_r (thread_name_copy, " ", &save_ptr);
  if (thread_name == NULL) {
    palloc_free_page (fn_copy);
    palloc_free_page (thread_name_copy);
    return TID_ERROR;
  }

  // create the child status record
  struct child_status *cur_status = palloc_get_page (0);
  if (cur_status == NULL) {
    palloc_free_page (fn_copy);
    palloc_free_page (thread_name_copy);
    return TID_ERROR;
  }
  enum intr_level old_level = intr_disable();
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    {
      palloc_free_page (cur_status);
      palloc_free_page (fn_copy);
      palloc_free_page (thread_name_copy);
      intr_set_level (old_level);
      return TID_ERROR;
    }
  
  palloc_free_page (thread_name_copy);
  /* Set up parent-child relationship */
  struct thread *child = thread_get_by_tid(tid);
  if (child != NULL)
    {
      // initialize child's child status record
      cur_status->pid = tid;
      cur_status->exit_status = -1;
      cur_status->exited = false;
      cur_status->waited = false;
      cur_status->load_success = false;  // Initialize load_success
      sema_init(&cur_status->sema, 0);
      // link child status record to child thread
      child->cstatus = cur_status;
      child->parent = thread_current();
      // add to parent's children list
      list_push_back(&thread_current()->children, &cur_status->elem);
    }
  
  if(child == NULL) {
      palloc_free_page (cur_status);
      intr_set_level (old_level);
      return TID_ERROR;
  }

  // wait for child to load
  sema_down(&child->load_done); 
  intr_set_level (old_level);
  if(!cur_status->load_success) {
      return TID_ERROR;
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  //give the load result to the parent
  if(thread_current()->cstatus != NULL) {
      thread_current()->cstatus->load_success = success;
  }
  /* If load failed, quit. */
  // Note: file_name is now the original command line, not allocated with palloc
  struct thread *cur = thread_current();
  sema_up(&cur->load_done);
  palloc_free_page (file_name);
  if (!success)
    {
      // Signal load failure to parent
      thread_exit();
    }


  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid) { 
  struct thread *cur = thread_current();
  struct child_status *child = NULL;

  // Find the child status record for the given child_tid
  struct list_elem *e;
  for (e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e)) {
    struct child_status *cur_child = list_entry(e, struct child_status, elem);
    if (cur_child->pid == child_tid) {
      child = cur_child;
      break;
    }
  }

  if(child == NULL) {
      return -1;
  }
  
  // check if we've already waited for this child
  if (child->waited)
    return -1;
  //mark we are waiting for this child
  child->waited = true;
  
  if(!child->exited) {
    sema_down(&child->sema);
  }
  
  // get the exit status
  int exit_status = child->exit_status;
  list_remove(&child->elem);
  palloc_free_page(child);
  
  return exit_status;
}

/* Free the current process's resources. */
void process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  //remove self from parent's children list
  if (cur->cstatus != NULL)
    {
      cur->cstatus->exited = true;
      cur->cstatus->exit_status = cur->exit_status;
      //signal() that this child has exited
      sema_up(&cur->cstatus->sema);
    }

    if(cur->executable != NULL) {
        lock_acquire (&filesys_lock);
        file_close(cur->executable);
        lock_release (&filesys_lock);
        cur->executable = NULL;
    }
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      frame_remove_owner(cur);
      page_table_destroy(&cur->spt);
      pagedir_destroy (pd);
    }
    
  /* Close all open files. */
  for (unsigned i = 2; i < PGSIZE / sizeof(struct file *); i++)
    {
      if (cur->fd_table && cur->fd_table[i] != NULL)
        {
          lock_acquire (&filesys_lock);
          file_close(cur->fd_table[i]);
          lock_release (&filesys_lock);
          cur->fd_table[i] = NULL;
        }
    }
  if (cur->fd_table)
    palloc_free_page(cur->fd_table);
}

/* Sets up the CPU for running user code in the current
   This function is called on every context switch. */
void process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp, const char *cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  page_table_init(&t->spt);


  /* Open executable: use only the program name (first token). */
  char *fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    goto done;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *save_ptr = NULL;
  char *prog = strtok_r (fn_copy, " ", &save_ptr);
  if (prog == NULL) {
    palloc_free_page (fn_copy);
    goto done;
  }
  lock_acquire (&filesys_lock);
  file = filesys_open (prog);
  lock_release (&filesys_lock);
  palloc_free_page (fn_copy);


  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  lock_acquire (&filesys_lock);
  file_deny_write(file);
  lock_release (&filesys_lock);
  t->executable = file;
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                         read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  /* If load failed and we have an executable file, clean it up */
  if (!success && file != NULL) {
    lock_acquire (&filesys_lock);
    file_allow_write(file);
    file_close(file);
    lock_release (&filesys_lock);
    t->executable = NULL;
  }
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      struct page *newP = NULL;
      if (page_read_bytes > 0) {
          newP = page_create_file (upage, file, ofs, page_read_bytes, page_zero_bytes, writable);
      } else {
          newP = page_create_zero (upage);
      }
      if (newP == NULL)
        return false;
      
      if (!page_install (&thread_current()->spt, newP)) {
          free(newP);
          return false;
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += page_read_bytes;  // Advance file offset
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack (void **esp, const char *cmdline)
{
  uint8_t *kpage;
  char *argv[128];
  int argc = 0;
  int i = 0;
  char *cur_token, *cur;
  void* stack_limit;

  // Parse cmdline into argv
  char *cmdline_copy = palloc_get_page(0);
  if (cmdline_copy == NULL)
    return false;
  strlcpy(cmdline_copy, cmdline, PGSIZE);
  cur_token = strtok_r (cmdline_copy, " ", &cur);
  while (cur_token != NULL && argc < 128) {
    argv[argc++] = cur_token;
    cur_token = strtok_r (NULL, " ", &cur);
  }
  argv[argc] = NULL; // Null-terminate the array

  // Allocate and map stack page
  kpage = frame_alloc (((uint8_t *) PHYS_BASE) - PGSIZE, true, true);
  if (kpage == NULL)
    {
      frame_free (kpage);
      return false;
    }
    
  if (!install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true)) {
    frame_free (kpage);
    return false;
  }
  struct page* p = page_create_zero (((uint8_t *) PHYS_BASE) - PGSIZE);
  if (p == NULL) {
    frame_free (kpage);
    frame_free(cmdline_copy);
    return false;
  }
  page_set_loaded (p, true);
  if (!page_install (&thread_current()->spt, p)) {
    free(p);
    frame_free (kpage);
    frame_free(cmdline_copy);
    return false;
  }


  
  // Set up stack with args
  *esp = (void *)PHYS_BASE;
  stack_limit = (void *)((uint8_t *)PHYS_BASE - PGSIZE);
  
  // Push argument strings (bottom-up)
  for (i = argc - 1; i >= 0; i--) {
    size_t len = strlen(argv[i]) + 1;
    //check overflow
    if((char *)*esp - len < (char *)stack_limit) {
      palloc_free_page(cmdline_copy);
      return false;
    }
    *esp = (char *)*esp - len;
    strlcpy((char *)*esp, argv[i], len);
    argv[i] = (char *)*esp;
  }
  // Word align to 4 bytes
  *esp = (void *)(((uintptr_t) *esp) & ~3);

  //check overflow
  if((char *)*esp - (argc + 1) * sizeof (char *) < (char*)stack_limit) {
    palloc_free_page(cmdline_copy);
    return false;
  }
  // Push argv array (pointers to argument strings)
  *esp = (char *)*esp - (argc + 1) * sizeof (char *);
  char **argv_ptr = (char **) *esp;
  
  // Copy argv pointers to stack
  for (i = 0; i < argc; i++) {
    argv_ptr[i] = argv[i];
  }
  argv_ptr[argc] = NULL;
  
  //check overflow
  if((char *)*esp - sizeof(char **) < (char *)stack_limit) {
    palloc_free_page(cmdline_copy);
    return false;
  }
  // Push argv pointer
  *esp = (char *)*esp - sizeof (char **);
  *(char ***) *esp = argv_ptr;

  //check overflow
  if((char *)*esp - sizeof(int) < (char *)stack_limit) {
    palloc_free_page(cmdline_copy);
    return false;
  }

  // Push argc
  *esp = (char *)*esp - sizeof(int);
  *(int *)*esp = argc;

  //check overflow
  if((char *)*esp - sizeof(void *) < (char *)stack_limit) {
    palloc_free_page(cmdline_copy);
    return false;
  }
  // Push return address
  *esp = (char *)*esp - sizeof(void *);
  *(void **)*esp = NULL;

  
  // Free the cmdline copy
  palloc_free_page(cmdline_copy);

  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL &&
          pagedir_set_page (t->pagedir, upage, kpage, writable));
}

