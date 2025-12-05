#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"
#include "devices/block.h"
#include "lib/kernel/console.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <string.h>
//lebron
/* Directory entry structure (matches directory.c) */
struct dir_entry
{
 block_sector_t inode_sector;
 char name[NAME_MAX + 1];
 bool in_use;
};

// standard file descriptor numbers
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/* Function declarations */
static void syscall_handler (struct intr_frame *);
static void validate_user_ptr (const void *ptr);
static void validate_user_buffer (const void *ptr, size_t size);
static void validate_user_string (const char *str);
static bool range_mapped (const void *usrc, size_t size);
static bool get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size);
static void halt (void);
static void exit (int status);
static int write (int fd, const void *buffer, unsigned size);
static int exec (const char *cmd_line);
static int wait (int child_tid);
static int read (int fd, void *buffer, unsigned size);
static int filesize_sys (int fd);
static bool chdir_sys (const char *dir);
static bool mkdir_sys (const char *dir);
static bool readdir_sys (int fd, char *name);
static bool isdir_sys (int fd);
static int inumber_sys (int fd);
int allocate_fd(struct file *file);
struct file *get_file_by_fd(int fd);
void close_fd(int fd);

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
 halt (); // power off the system
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
 exit (status); // terminate process with status
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
 
 case SYS_EXEC:
 {
 const char *cmd_line;
 
 // safely read exec argument from user stack
 if (!get_user_bytes ((uint8_t *) &cmd_line, (uint8_t *) (esp + 1), sizeof (const char *)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 
 // validate the command line pointer is in user space
 validate_user_string (cmd_line);
 
 // call our exec implementation and set return value
 int result = exec (cmd_line); // start new process
 f->eax = result;
 }
 break;
 
 case SYS_WAIT:
 {
 int child_tid;
 
 // safely read wait argument from user stack
 if (!get_user_bytes ((uint8_t *) &child_tid, (uint8_t *) (esp + 1), sizeof (int)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 
 // call our wait implementation and set return value
 int result = wait (child_tid); // wait for child process
 f->eax = result;
 }
 break;
 
 case SYS_READ:
 {
 int fd;
 void *buffer;
 unsigned size;
 
 // safely read arguments from user stack
 if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int)) ||
 !get_user_bytes ((uint8_t *) &buffer, (uint8_t *) (esp + 2), sizeof (void *)) ||
 !get_user_bytes ((uint8_t *) &size, (uint8_t *) (esp + 3), sizeof (unsigned)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 
 // validate the buffer pointer is in user space
 validate_user_ptr (buffer);
 
 // call our read implementation and set return value
 int result = read (fd, buffer, size); // read from stdin only
 f->eax = result;
 }
 break;
 
 case SYS_CREATE: 
 {
 const char *file;
 unsigned initial_size;
 if (!get_user_bytes ((uint8_t *) &file, (uint8_t *) (esp + 1), sizeof (const char *)) ||
 !get_user_bytes ((uint8_t *) &initial_size, (uint8_t *) (esp + 2), sizeof (unsigned)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 if (file == NULL) {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 validate_user_string(file);
 f->eax = filesys_create(file, initial_size);
 }
 break;

 case SYS_REMOVE: 
 {
 const char *file;
 unsigned initial_size;
 if (!get_user_bytes ((uint8_t *) &file, (uint8_t *) (esp + 1), sizeof (const char *)) ||
 !get_user_bytes ((uint8_t *) &initial_size, (uint8_t *) (esp + 2), sizeof (unsigned)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 if (file == NULL) {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 validate_user_string(file);
 f->eax = filesys_remove(file);
 }
 break;

 case SYS_OPEN:
 {
 const char *file_name;
 if (!get_user_bytes((uint8_t *)&file_name, (uint8_t *)(esp + 1), sizeof(file_name)))
 thread_exit(); 

 validate_user_string(file_name); 

 struct file *file = filesys_open(file_name); 

 if (file == NULL)
 {
 f->eax = -1; 
 }
 else
 {
 f->eax = allocate_fd(file); 
 if (f->eax == -1) {
 file_close(file);
 }
 }
 break;
 }

 case SYS_CLOSE:
 {
 int fd;
 if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(fd)))
 thread_exit(); 

 close_fd(fd); 
 break;
 }

 case SYS_FILESIZE:
 {
 int fd;
 if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(fd)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 f->eax = filesize_sys(fd);
 break;
 }
 case SYS_SEEK:
 {
 int fd;
 unsigned position;
 if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(int)) ||
 !get_user_bytes((uint8_t *)&position, (uint8_t *)(esp + 2), sizeof(unsigned)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 struct file *fptr = get_file_by_fd(fd);
 if (fptr != NULL)
 {
 file_seek(fptr, position);
 }
 break;
 }
 case SYS_TELL:
 {
 int fd;
 if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(int)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 struct file *fptr = get_file_by_fd(fd);
 if (fptr == NULL)
 {
 f->eax = -1;
 }
 else
 {
 f->eax = file_tell(fptr);
 }
 break;
 }

 case SYS_CHDIR:
 {
 const char *dir;
 if (!get_user_bytes ((uint8_t *) &dir, (uint8_t *) (esp + 1), sizeof (const char *)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 if (dir == NULL)
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 validate_user_string (dir);
 f->eax = chdir_sys (dir);
 break;
 }

 case SYS_MKDIR:
 {
 const char *dir;
 if (!get_user_bytes ((uint8_t *) &dir, (uint8_t *) (esp + 1), sizeof (const char *)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 if (dir == NULL)
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 validate_user_string (dir);
 f->eax = mkdir_sys (dir);
 break;
 }

 case SYS_READDIR:
 {
 int fd;
 char *name;
 if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int)) ||
 !get_user_bytes ((uint8_t *) &name, (uint8_t *) (esp + 2), sizeof (char *)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 if (name == NULL)
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 validate_user_ptr (name);
 f->eax = readdir_sys (fd, name);
 break;
 }

 case SYS_ISDIR:
 {
 int fd;
 if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 f->eax = isdir_sys (fd);
 break;
 }

 case SYS_INUMBER:
 {
 int fd;
 if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int)))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
 f->eax = inumber_sys (fd);
 break;
 }

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
 // use range_mapped to check the entire range
 if (!range_mapped (ptr, size))
 {
 printf ("%s: exit(-1)\n", thread_name ());
 thread_exit ();
 }
}

// returns if the entire [usrc, usrc+size-1] lies in user space
// and every overlapped page is mapped in the current process.
static bool
range_mapped (const void *usrc, size_t size)
{
 if (size == 0)
 return true;
 if (usrc == NULL)
 return false;

 const uint8_t *start = (const uint8_t *) usrc;
 const uint8_t *last = start + size - 1;

 if (!is_user_vaddr (start) || !is_user_vaddr (last))
 return false;

 uint8_t *p = pg_round_down ((void *) start);
 uint8_t *end = pg_round_down ((void *) last);

 struct thread *cur = thread_current ();
 if (cur == NULL || cur->pagedir == NULL)
 return false;

 while (p <= end)
 {
 if (pagedir_get_page (cur->pagedir, p) == NULL)
 return false;
 p += PGSIZE;
 }
 return true;
}

// safely reads size bytes from user address to kernel address
// validates the user address range first
static bool
get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size)
{
 if (size == 0)
 return true;

 // validate the entire range, including the last page
 if (!range_mapped (usrc, size))
 return false;

 // now it's safe to copy
 for (size_t i = 0; i < size; i++)
 dst[i] = usrc[i];
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

// validates that a null-terminated string is in user space and mapped
static void validate_user_string(const char *str)
{
 if (str == NULL || !is_user_vaddr(str))
 {
 printf("%s: exit(-1)\n", thread_name());
 thread_exit();
 }

 const char *ptr = str;
 struct thread *cur = thread_current();

 while (true)
 {
 // check if the current pointer is in user space and mapped
 if (!is_user_vaddr(ptr) || pagedir_get_page(cur->pagedir, (void *)ptr) == NULL)
 {
 printf("%s: exit(-1)\n", thread_name());
 thread_exit();
 }

 if (*ptr == '\0')
 break;

 // move to next char
 ptr++;
 }
}

// halt system call - powers off the system
static void halt (void)
{
 shutdown_power_off (); // call kernel shutdown function
}

// exit system call - terminates the current process
static void exit (int status)
{
 struct thread *cur = thread_current ();
 cur->exit_status = status; // store exit status for parent to read
 printf ("%s: exit(%d)\n", thread_name (), status); // print exit message
 thread_exit (); // terminate the thread
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
 struct file *temp = get_file_by_fd(fd);
 if (temp == NULL) {
 return -1;
 }
 struct inode *inode = file_get_inode (temp);
 if (inode == NULL) {
 return -1;
 }
 if (is_inode_dir (inode)) {
 return -1;
 }
 validate_user_buffer (buffer, size);
 int bytes_written = file_write(temp, buffer, size);
 return bytes_written;
 }
}

// exec system call - starts another process
static int exec (const char *cmd_line)
{
 // validate the command line string is in user space
 validate_user_ptr (cmd_line);
 validate_user_string (cmd_line);
 
 // start the new process and return its thread id
 tid_t tid = process_execute (cmd_line);

 // if process_execute returns TID_ERROR, return -1
 if (tid == TID_ERROR)
 return -1;

 // otherwise return the thread id
 return tid;
}

// wait system call - waits for a child process to complete
static int wait (int child_tid)
{
 // call the process_wait function and return its result
 return process_wait (child_tid);
}

// read system call - reads from a file descriptor
static int read (int fd, void *buffer, unsigned size)
{
 if (fd == STDIN_FILENO)
 {
 // validate buffer before reading
 validate_user_buffer (buffer, size);
 
 // read from keyboard
 unsigned i;
 for (i = 0; i < size; i++)
 {
 ((char *) buffer)[i] = input_getc ();
 }
 return size;
 }
 else
 {
 struct file *temp = get_file_by_fd(fd);
 if (temp == NULL) {
 return -1;
 }
 validate_user_buffer (buffer, size);
 int bytes_read = file_read(temp, buffer, size);
 if (bytes_read < 0) {
 printf("file_read failed for fd %d\n", fd);
 }
 return bytes_read;

 }
}

static int filesize_sys (int fd)
{
 struct file *f = get_file_by_fd(fd);
 if (f == NULL)
 return -1;
 int length = file_length(f);
 return length;
}

int allocate_fd(struct file *file) {
 struct thread *cur = thread_current();
 if (cur->fd_table == NULL)
 return -1;

 // find the next available fd
 int fd = cur->fd_next;
 while (fd < 128) {
 if (cur->fd_table[fd] == NULL) {
 cur->fd_table[fd] = file; // assign the file to this fd
 // update fd_next for next allocation
 cur->fd_next = fd + 1;
 return fd;
 }
 fd++;
 }
 return -1; // no available fd
}

struct file *get_file_by_fd(int fd) {
 struct thread *cur = thread_current();
 if (cur->fd_table == NULL || fd < 0 || fd > 128)
 return NULL; // invalid fd or fd table not initialized
 return cur->fd_table[fd];
}

void close_fd(int fd) {
 struct thread *cur = thread_current();
 if (cur->fd_table == NULL || fd < 0 || fd > 128)
 return;
 if (cur->fd_table[fd] != NULL) {
 file_close(cur->fd_table[fd]);
 cur->fd_table[fd] = NULL;
 // update fd_next to allow reusing lower fds
 if (fd < cur->fd_next)
 cur->fd_next = fd;
 }
}

static bool chdir_sys (const char *dir)
{
 if (dir == NULL)
 return false;
 
 struct file *dir_file = filesys_open (dir);
 if (dir_file == NULL)
 return false;
 
 struct inode *inode = file_get_inode (dir_file);
 if (!is_inode_dir (inode))
 {
 file_close (dir_file);
 return false;
 }
 
 struct thread *cur = thread_current ();
 struct dir *new_cwd = dir_open (inode_reopen (inode));
 file_close (dir_file);
 
 if (new_cwd == NULL)
 return false;
 
 if (cur->cwd != NULL)
 dir_close (cur->cwd);
 
 cur->cwd = new_cwd;
 return true;
}

static bool mkdir_sys (const char *dir)
{
 if (dir == NULL)
 return false;
 
 return filesys_mkdir (dir);
}

static bool readdir_sys (int fd, char *name)
{
 if (fd < 0 || fd > 128 || name == NULL)
 return false;
 
 struct file *file = get_file_by_fd (fd);
 if (file == NULL)
 return false;
 
 struct inode *inode = file_get_inode (file);
 if (!is_inode_dir (inode))
 return false;
 
 struct dir_entry e;
 off_t pos = file_tell (file);
 while (inode_read_at (inode, &e, sizeof e, pos) == sizeof e)
 {
 pos += sizeof e;
 file_seek (file, pos);
 if (e.in_use)
 {
 if (strcmp(e.name, ".") == 0 || strcmp(e.name, "..") == 0) {
 continue;
 }
 if (e.name[0] == '\0') {
 continue;
 }
 strlcpy (name, e.name, NAME_MAX + 1);
 return true;
 }
 }
 return false;
}

static bool isdir_sys (int fd)
{
 if (fd < 0 || fd > 128)
 return false;
 
 struct file *file = get_file_by_fd (fd);
 if (file == NULL)
 return false;
 
 struct inode *inode = file_get_inode (file);
 return is_inode_dir (inode);
}

static int inumber_sys (int fd)
{
 if (fd < 0 || fd > 128)
 return -1;
 
 struct file *file = get_file_by_fd (fd);
 if (file == NULL)
 return -1;
 
 struct inode *inode = file_get_inode (file);
 return (int) inode_get_inumber (inode);
}