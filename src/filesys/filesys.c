#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void) { free_map_close (); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME alreadysts,
   or if internal memory allocation fails. */
bool filesys_create (const char *name, off_t initial_size)
{
  if (name == NULL || *name == '\0')
    return false;
  
  struct dir *dir = NULL;
  char *file_name = NULL;
  bool success = false;
  block_sector_t inode_sector = 0;
  
  if (!get_dir_and_name (name, &dir, &file_name))
    return false;
  
  if (*file_name == '\0')
    {
      /* Cannot create a directory with this function */
      dir_close (dir);
      free (file_name);
      return false;
    }
  
  success = (dir != NULL && free_map_allocate (1, &inode_sector) &&
             inode_create (inode_sector, initial_size, false) &&
             dir_add (dir, file_name, inode_sector));
  
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  
  dir_close (dir);
  free (file_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
  if (name == NULL || *name == '\0')
    return NULL;
  
  struct dir *dir = NULL;
  char *file_name = NULL;
  struct inode *inode = NULL;
  
  if (!get_dir_and_name (name, &dir, &file_name))
    return NULL;
  
  if (*file_name == '\0')
    {
      /* Opening a directory - return the directory's inode as a file */
      inode = dir_get_inode (dir);
      if (inode != NULL)
        {
          if (inode_is_removed (inode))
            {
              dir_close (dir);
              free (file_name);
              return NULL;
            }
          inode_reopen (inode);
        }
      dir_close (dir);
      free (file_name);
      return file_open (inode);
    }
  
  if (dir != NULL)
    dir_lookup (dir, file_name, &inode);
  
  dir_close (dir);
  free (file_name);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *name)
{
  if (name == NULL || *name == '\0')
    return false;
  
  struct dir *dir = NULL;
  char *file_name = NULL;
  bool success = false;
  
  if (!get_dir_and_name (name, &dir, &file_name))
    return false;
  
  if (*file_name == '\0')
    {
      /* Cannot remove root directory */
      dir_close (dir);
      free (file_name);
      return false;
    }
  
  //ensure we can't remove the cwd and ancestors
  struct inode *target_inode = NULL;
  if (dir_lookup (dir, file_name, &target_inode))
    {
      struct dir *cwd = thread_current ()->cwd;
      if (cwd != NULL)
        {
           if (inode_get_inumber (target_inode) == inode_get_inumber (dir_get_inode (cwd)))
             {
               inode_close (target_inode);
               dir_close (dir);
               free (file_name);
               return false;
             }
        }
      inode_close (target_inode);
    }

  success = dir != NULL && dir_remove (dir, file_name);
  
  dir_close (dir);
  free (file_name);

  return success;
}

/* Creates a directory named DIR.
   Returns true if successful, false on failure.
   Fails if a directory named DIR already exists,
   or if any directory name in DIR, besides the last, does not already exist. */
bool filesys_mkdir (const char *dir)
{
  if (dir == NULL || *dir == '\0')
    return false;
  
  struct dir *parent_dir = NULL;
  char *dir_name = NULL;
  bool success = false;
  block_sector_t inode_sector = 0;
  
  if (!get_dir_and_name (dir, &parent_dir, &dir_name))
    return false;
  
  if (*dir_name == '\0')
    {
      /* Cannot create root directory */
      dir_close (parent_dir);
      free (dir_name);
      return false;
    }
  
  if (free_map_allocate (1, &inode_sector))
    {
      struct inode *parent_inode = dir_get_inode (parent_dir);
      block_sector_t parent_sector = inode_get_inumber (parent_inode);
      
      if (dir_create (inode_sector, 16, parent_sector) &&
          dir_add (parent_dir, dir_name, inode_sector))
        {
          success = true;
        }
      
      if (!success && inode_sector != 0)
        free_map_release (inode_sector, 1);
    }
  
  dir_close (parent_dir);
  free (dir_name);
  
  return success;
}

/* Formats the file system. */
static void do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}