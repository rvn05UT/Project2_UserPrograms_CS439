#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/console.h"

// standard file descriptor numbers
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/* Function declarations */
static void syscall_handler (struct intr_frame *);
static void validate_user_ptr (const void *ptr);
static void validate_user_buffer (const void *ptr, size_t size);
static bool get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size);
static bool put_user_bytes (uint8_t *udst, const uint8_t *src, size_t size);
static void halt (void);
static void exit (int status);
static int write (int fd, const void *buffer, unsigned size);

void syscall_init (void)
{
  // register our system call handler for interrupt 0x30
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  uint32_t *esp = (uint32_t *) f->esp;
  
  // validate the stack pointer is in user space
  validate_user_ptr ((void *) esp);
  
  // safely read the system call number from user stack
  if (!get_user_bytes ((uint8_t *) &syscall_number, (uint8_t *) esp, sizeof (int)))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
  
  // dispatch to the appropriate system call handler
  switch (syscall_number)
    {
      case SYS_HALT:
        halt ();
        break;
        
      case SYS_EXIT:
        {
          int status;
          // safely read the exit status from user stack
          if (!get_user_bytes ((uint8_t *) &status, (uint8_t *) (esp + 1), sizeof (int)))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          exit (status);
        }
        break;
        
      case SYS_WRITE:
        {
          int fd;
          void *buffer;
          unsigned size;
          
          // safely read write arguments from user stack
          if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int)) ||
              !get_user_bytes ((uint8_t *) &buffer, (uint8_t *) (esp + 2), sizeof (void *)) ||
              !get_user_bytes ((uint8_t *) &size, (uint8_t *) (esp + 3), sizeof (unsigned)))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          
          // validate the buffer pointer is in user space
          validate_user_ptr (buffer);
          
          // call our write implementation and set return value
          int result = write (fd, buffer, size);
          f->eax = result;
        }
        break;
        
      default:
        // unknown system call - terminate process
        printf ("%s: exit(-1)\n", thread_name ());
        thread_exit ();
    }
}

// validates that a range of user memory is valid
// terminates the process if invalid
static void
validate_user_buffer (const void *ptr, size_t size)
{
  // check if pointer is null or not in user space
  if (ptr == NULL || !is_user_vaddr (ptr))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
  
  // check if the entire range is in user space
  const uint8_t *start = (const uint8_t *) ptr;
  const uint8_t *end = start + size;
  
  if (!is_user_vaddr (end - 1))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
}

// safely reads size bytes from user address to kernel address
// validates the user address range first
static bool
get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size)
{
  validate_user_buffer (usrc, size);
  
  // now it's safe to copy
  for (size_t i = 0; i < size; i++)
    dst[i] = usrc[i];
  return true;
}

// safely writes size bytes from kernel address to user address
// validates the user address range first
static bool
put_user_bytes (uint8_t *udst, const uint8_t *src, size_t size)
{
  validate_user_buffer (udst, size);
  
  // now it's safe to copy
  for (size_t i = 0; i < size; i++)
    udst[i] = src[i];
  return true;
}

// validates that a single pointer is in user space
static void
validate_user_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
}

// halt system call - powers off the system
static void halt (void)
{
  shutdown_power_off ();
}

// exit system call - terminates the current process
static void exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf ("%s: exit(%d)\n", thread_name (), status);
  thread_exit ();
}

// write system call - writes data to a file descriptor
static int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
    {
      // validate buffer before writing
      validate_user_buffer (buffer, size);
      
      // write to console
      putbuf (buffer, size);
      return size;
    }
  else
    {
      // for now, only support stdout
      return -1;
    }
}
