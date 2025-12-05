#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* A directory. */
struct dir
{
  struct inode *inode; /* Backing store. */
  off_t pos;           /* Current position. */
};

/* A single directory entry. */
struct dir_entry
{
  block_sector_t inode_sector; /* Sector number of header. */
  char name[NAME_MAX + 1];     /* Null terminated file name. */
  bool in_use;                 /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create (block_sector_t sector, size_t entry_cnt, block_sector_t parent_sector)
{
   if(!inode_create (sector, entry_cnt * sizeof (struct dir_entry), true)) {
        return false;
   }
   struct dir *sub = dir_open (inode_open (sector));
   if (sub == NULL) {
       return false;
   }
   if (dir_add (sub, ".", sector) == false) {
       dir_close (sub);
       return false;
   }
    if (dir_add (sub, "..", parent_sector) == false) {
        dir_close (sub);
        return false;
    }
    dir_close (sub);
    return true;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *dir_open (struct inode *inode)
{
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *dir_reopen (struct dir *dir)
{
  return dir_open (inode_reopen (dir->inode));
}

// closes the inode associated with the directory
void dir_close (struct dir *dir)
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode *dir_get_inode (struct dir *dir) { return dir->inode; }

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup (const struct dir *dir, const char *name,
                    struct dir_entry *ep, off_t *ofsp)
{
  struct dir_entry e;
  size_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use && !strcmp (name, e.name))
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **inode)
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove (struct dir *dir, const char *name)
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;
  
  if (is_inode_dir(inode)) {
      struct dir *sub_dir = dir_open(inode_reopen(inode));
      if (sub_dir == NULL) {
          goto done;
      }
      bool is_empty = dir_is_empty(sub_dir);
      dir_close(sub_dir);
      if (!is_empty) {
          goto done;
      }
      
      // can't remove inode open multiple times
      if (inode_get_open_cnt(inode) > 1) {
          goto done;
      }
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

done:
  inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e)
    {
      dir->pos += sizeof e;
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
bool dir_is_empty(struct dir *dir) 
{
  struct dir_entry e;
  off_t ofs;

  ASSERT (dir != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e)
    if (e.in_use)
      {
        if (e.name[0] == '\0') {
            continue;
        }
        if (strcmp(e.name, ".") != 0 && strcmp(e.name, "..") != 0) {
            return false;
        }
      }
  return true;
}

/* Normalizes a path by removing multiple consecutive slashes and trailing slashes.
   Returns a newly allocated string that the caller must free. */
static char *normalize_path (const char *path)
{
  if (path == NULL || *path == '\0')
    return NULL;
  
  size_t len = strlen (path);
  char *normalized = malloc (len + 1);
  if (normalized == NULL)
    return NULL;
  
  const char *src = path;
  char *dst = normalized;
  bool last_was_slash = false;
  
  while (*src != '\0')
    {
      if (*src == '/')
        {
          if (!last_was_slash)
            {
              *dst++ = '/';
              last_was_slash = true;
            }
        }
      else
        {
          *dst++ = *src;
          last_was_slash = false;
        }
      src++;
    }
  
  /* Remove trailing slash unless it's the root */
  if (dst > normalized + 1 && *(dst - 1) == '/')
    dst--;
  
  *dst = '\0';
  return normalized;
}

/* Splits a path into directory path and file name.
   Returns true on success, false on failure.
   On success, *dir_path and *file_name are newly allocated strings that caller must free. */
static bool split_path (const char *path, char **dir_path, char **file_name)
{
  if (path == NULL)
    return false;
  
  char *normalized = normalize_path (path);
  if (normalized == NULL)
    return false;
  
  size_t len = strlen (normalized);
  
  /* Find the last slash */
  const char *last_slash = strrchr (normalized, '/');
  
  if (last_slash == NULL)
    {
      /* No slash - entire path is the file name, directory is current directory */
      *dir_path = malloc (2);
      if (*dir_path != NULL)
        strlcpy (*dir_path, ".", 2);
      *file_name = malloc (strlen (normalized) + 1);
      if (*file_name != NULL)
        strlcpy (*file_name, normalized, strlen (normalized) + 1);
    }
  else if (last_slash == normalized)
    {
      /* Path starts with / and has no other slashes - root directory */
      if (len == 1)
        {
          /* Just "/" - root directory itself */
          *dir_path = malloc (2);
          if (*dir_path != NULL)
            strlcpy (*dir_path, "/", 2);
          *file_name = malloc (1);
          if (*file_name != NULL)
            (*file_name)[0] = '\0';
        }
      else
        {
          /* "/filename" - root is directory, rest is filename */
          *dir_path = malloc (2);
          if (*dir_path != NULL)
            strlcpy (*dir_path, "/", 2);
          size_t file_name_len = strlen (normalized + 1) + 1;
          *file_name = malloc (file_name_len);
          if (*file_name != NULL)
            strlcpy (*file_name, normalized + 1, file_name_len);
        }
    }
  else
    {
      /* Has directory and file components */
      size_t dir_len = last_slash - normalized;
      *dir_path = malloc (dir_len + 1);
      if (*dir_path == NULL)
        {
          free (normalized);
          return false;
        }
      memcpy (*dir_path, normalized, dir_len);
      (*dir_path)[dir_len] = '\0';
      
      size_t file_name_len = strlen (last_slash + 1) + 1;
      *file_name = malloc (file_name_len);
      if (*file_name != NULL)
        strlcpy (*file_name, last_slash + 1, file_name_len);
    }
  
  free (normalized);
  return (*dir_path != NULL && *file_name != NULL);
}

/* Resolves a path (absolute or relative) and returns the directory and final component.
   Returns true on success, false on failure.
   On success, *dir is the directory (caller must close) and *name is the final component.
   *name is a newly allocated string that caller must free. */
bool get_dir_and_name (const char *path, struct dir **dir, char **name)
{
  if (path == NULL || *path == '\0')
    return false;
  
  char *dir_path = NULL;
  char *file_name = NULL;
  
  if (!split_path (path, &dir_path, &file_name))
    return false;
  
  /* Resolve the directory path */
  struct dir *resolved_dir = NULL;
  
  if (strcmp (dir_path, "/") == 0)
    {
      /* Root directory */
      resolved_dir = dir_open_root ();
    }
  else if (strcmp (dir_path, ".") == 0)
    {
      /* Current directory */
      struct thread *cur = thread_current ();
      if (cur->cwd == NULL)
        resolved_dir = dir_open_root ();
      else
        {
          struct inode *cwd_inode = dir_get_inode (cur->cwd);
          if (cwd_inode != NULL && inode_is_removed (cwd_inode))
            {
              free (dir_path);
              free (file_name);
              return false;
            }
          resolved_dir = dir_reopen (cur->cwd);
        }
    }
  else
    {
      /* Need to resolve the path */
      bool is_absolute = (*dir_path == '/');
      struct dir *start_dir;
      
      if (is_absolute)
        start_dir = dir_open_root ();
      else
        {
          struct thread *cur = thread_current ();
          if (cur->cwd == NULL)
            start_dir = dir_open_root ();
          else
            start_dir = dir_reopen (cur->cwd);
        }
      
      if (start_dir == NULL)
        {
          free (dir_path);
          free (file_name);
          return false;
        }
      
      /* Tokenize the path and traverse */
      char *save_ptr;
      char *token = strtok_r (is_absolute ? dir_path + 1 : dir_path, "/", &save_ptr);
      resolved_dir = start_dir;
      
      while (token != NULL)
        {
          struct inode *next_inode = NULL;
          
          if (strcmp (token, ".") == 0)
            {
              /* Stay in current directory */
              token = strtok_r (NULL, "/", &save_ptr);
              continue;
            }
          else if (strcmp (token, "..") == 0)
            {
              /* Go to parent directory */
              struct inode *parent_inode = NULL;
              if (dir_lookup (resolved_dir, "..", &parent_inode))
                {
                  dir_close (resolved_dir);
                  resolved_dir = dir_open (parent_inode);
                  if (resolved_dir == NULL)
                    {
                      inode_close (parent_inode);
                      free (dir_path);
                      free (file_name);
                      return false;
                    }
                }
              else
                {
                  dir_close (resolved_dir);
                  free (dir_path);
                  free (file_name);
                  return false;
                }
            }
          else
            {
              /* Look up the component */
              if (!dir_lookup (resolved_dir, token, &next_inode))
                {
                  dir_close (resolved_dir);
                  free (dir_path);
                  free (file_name);
                  return false;
                }
              
              if (!is_inode_dir (next_inode))
                {
                  inode_close (next_inode);
                  dir_close (resolved_dir);
                  free (dir_path);
                  free (file_name);
                  return false;
                }
              
              dir_close (resolved_dir);
              resolved_dir = dir_open (next_inode);
              if (resolved_dir == NULL)
                {
                  inode_close (next_inode);
                  free (dir_path);
                  free (file_name);
                  return false;
                }
            }
          
          token = strtok_r (NULL, "/", &save_ptr);
        }
    }
  
  free (dir_path);
  
  if (resolved_dir == NULL)
    {
      free (file_name);
      return false;
    }
  
  *dir = resolved_dir;
  *name = file_name;
  return true;
}