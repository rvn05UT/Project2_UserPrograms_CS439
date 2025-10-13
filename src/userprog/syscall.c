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


#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static void syscall_handler (struct intr_frame *);

void syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  int syscall_number;
  
  validate_user_ptr ((void *) f->esp);
  
  if (!get_user_bytes ((uint8_t *) &syscall_number, (uint8_t *) f->esp, sizeof (int)))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
  
  switch (syscall_number)
    {
      case SYS_HALT:
        halt ();
        break;
        
      case SYS_EXIT:
        {
          int status;
          if (!get_user_bytes ((uint8_t *) &status, (uint8_t *) (f->esp + 4), sizeof (int)))
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
          
          if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (f->esp + 4), sizeof (int)) ||
              !get_user_bytes ((uint8_t *) &buffer, (uint8_t *) (f->esp + 8), sizeof (void *)) ||
              !get_user_bytes ((uint8_t *) &size, (uint8_t *) (f->esp + 12), sizeof (unsigned)))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          
          validate_user_ptr (buffer);
          
          int result = write (fd, buffer, size);
          f->eax = result;
        }
        break;
        
      default:
        printf ("%s: exit(-1)\n", thread_name ());
        thread_exit ();
    }
}

static int get_user(const uint8_t *uaddr) {
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool put_user(uint8_t *uaddr, int value) {
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code == 0;
}

static bool
get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size)
{
  for (size_t i = 0; i < size; i++)
    {
      int byte = get_user (usrc + i);
      if (byte == -1)
        return false;
      dst[i] = byte;
    }
  return true;
}

static bool
put_user_bytes (uint8_t *udst, const uint8_t *src, size_t size)
{
  for (size_t i = 0; i < size; i++)
    if (!put_user (udst + i, src[i]))
      return false;
  return true;
}

static void
validate_user_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
}

static void halt (void)
{
  shutdown_power_off ();
}

static void exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf ("%s: exit(%d)\n", thread_name (), status);
  thread_exit ();
}

static int write (int fd, const void *buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      return size;
    }
  else
    {
      return -1;
    }
}
