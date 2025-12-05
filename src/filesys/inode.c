#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

// indirect block wrapper
struct indirect_block {
  block_sector_t direct[128];
};

// double indirect block wrapper
struct doubly_indirect_block {
  block_sector_t indirect[128];
};
#include "threads/synch.h"

// indirect block wrapper
struct indirect_block {
  block_sector_t direct[128];
};

// double indirect block wrapper
struct doubly_indirect_block {
  block_sector_t indirect[128];
};

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  block_sector_t direct[12]; /* Direct sectors. blocks 0-11 */
  block_sector_t indirect; /* indirect sector. blocks 12-139*/
  block_sector_t double_indirect; /* doubly indirect sector. blocks 139 - 16522*/
  off_t length;         /* File size in bytes. */
  unsigned magic;       /* Magic number. */
  uint32_t is_dir;      /* True if directory, false if file */
  uint32_t unused[111]; /* Not used, ensures offset to 512 bytes */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
  struct lock inode_lock;   /* Lock for synchronizing access to inode */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);

  if (pos < inode->data.length) {
    size_t sector = pos / BLOCK_SECTOR_SIZE;
    if (sector < 12) {
      block_sector_t s = inode->data.direct[sector];
      return s ? s : (block_sector_t)-1;

    } 
    else if (sector < 140) {
      if(inode->data.indirect == 0) {
        return (block_sector_t)-1;
      }
      //get direct by reading indirect
      struct indirect_block indirect;
      block_read(fs_device, inode->data.indirect, &indirect);
      
      block_sector_t s = indirect.direct[sector - 12];
      return s ? s : (block_sector_t)-1;

    } else {
      if(inode->data.double_indirect == 0) {
        return (block_sector_t)-1;
      }

      sector = sector - 140; //offset into doubly indirect
      
      size_t level_1 = sector / 128;
      size_t level_2 = sector % 128;
      //get double indirect
      struct doubly_indirect_block d_indirect;
      block_read(fs_device, inode->data.double_indirect, &d_indirect);
      //get indirect from double indirect
      block_sector_t indirect_sec = d_indirect.indirect[level_1];
      if(indirect_sec == 0) {
        return (block_sector_t)-1;
      }
      struct indirect_block indirect;
      block_read(fs_device, indirect_sec, &indirect);

      block_sector_t s = indirect.direct[level_2];
      return s ? s : (block_sector_t)-1;
    }

    return -1;
  }
  else {
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
static struct lock inode_list_lock;

/* Initializes the inode module. */
void inode_init (void) { 
  list_init (&open_inodes); 
  lock_init (&inode_list_lock);
  }

//heler: ensures a block is allocated
static bool alloc_data_block (block_sector_t *out)
{
  if (!free_map_allocate (1, out))
    return false;
  char zeros[BLOCK_SECTOR_SIZE];
  block_write (fs_device, *out, zeros);
  return true;
}

//helper: ensures an indirect block is allocated
static bool ensure_indirect (block_sector_t *indirect_sec)
{
  if (*indirect_sec != 0) {
    return true;
  }
  if (!free_map_allocate (1, indirect_sec)) {
    return false;
  }
  struct indirect_block indirect;
  memset (&indirect, 0, sizeof indirect);
  block_write (fs_device, *indirect_sec, &indirect);
  return true;
}

//helper: ensures a double indirect block is allocated
static bool ensure_double_indirect (block_sector_t *double_indirect_sec)
{
  if (*double_indirect_sec != 0) {
    return true;
  }
  if (!free_map_allocate (1, double_indirect_sec)) {
    return false;
  }
  struct doubly_indirect_block d_indirect;
  memset (&d_indirect, 0, sizeof d_indirect);
  block_write (fs_device, *double_indirect_sec, &d_indirect);
  return true;
}

//gets or allocates the sector for a given sector index within an inode
static block_sector_t get_or_allocate_sector (struct inode_disk *disk_inode, size_t sector_idx)
{
  ASSERT (disk_inode != NULL);
  
  if (sector_idx < 12) {
    if (disk_inode->direct[sector_idx] == 0) {
      if (!alloc_data_block (&disk_inode->direct[sector_idx])) {
        return 0;
      }
    }
    return disk_inode->direct[sector_idx];
  }
  else if (sector_idx < 140) {
    if (!ensure_indirect (&disk_inode->indirect)) {
      return 0;
    }
    
    struct indirect_block indirect;
    block_read (fs_device, disk_inode->indirect, &indirect);
    
    size_t idx = sector_idx - 12;
    if (indirect.direct[idx] == 0) {
      if (!alloc_data_block (&indirect.direct[idx])) {
        return 0;
      }
      block_write (fs_device, disk_inode->indirect, &indirect);
    }
    return indirect.direct[idx];
  }
  else {
    if (!ensure_double_indirect (&disk_inode->double_indirect)) {
      return 0;
    }
    
    struct doubly_indirect_block d_indirect;
    block_read (fs_device, disk_inode->double_indirect, &d_indirect);
    
    size_t offset = sector_idx - 140;
    size_t level_1 = offset / 128;
    size_t level_2 = offset % 128;
    
    if (d_indirect.indirect[level_1] == 0) {
      if (!ensure_indirect (&d_indirect.indirect[level_1])) {
        return 0;
      }
      block_write (fs_device, disk_inode->double_indirect, &d_indirect);
    }
    
    struct indirect_block indirect;
    block_read (fs_device, d_indirect.indirect[level_1], &indirect);
    
    if (indirect.direct[level_2] == 0) {
      if (!alloc_data_block (&indirect.direct[level_2])) {
        return 0;
      }
      block_write (fs_device, d_indirect.indirect[level_1], &indirect);
    }
    return indirect.direct[level_2];
  }
}

//helper: frees all blocks allocated for an inode
static void free_inode_blocks (struct inode_disk *disk_inode)
{
  ASSERT (disk_inode != NULL);
  
  size_t sectors = bytes_to_sectors (disk_inode->length);
  
  for (size_t i = 0; i < 12 && i < sectors; i++) {
    if (disk_inode->direct[i] != 0) {
      free_map_release (disk_inode->direct[i], 1);
    }
  }
  
  if (disk_inode->indirect != 0 && sectors > 12) {
    struct indirect_block indirect;
    block_read (fs_device, disk_inode->indirect, &indirect);
    
    size_t indirect_sectors = sectors > 140 ? 128 : sectors - 12;
    for (size_t i = 0; i < indirect_sectors; i++) {
      if (indirect.direct[i] != 0) {
        free_map_release (indirect.direct[i], 1);
      }
    }
    free_map_release (disk_inode->indirect, 1);
  }
  
  if (disk_inode->double_indirect != 0 && sectors > 140) {
    struct doubly_indirect_block d_indirect;
    block_read (fs_device, disk_inode->double_indirect, &d_indirect);
    
    size_t remaining_sectors = sectors - 140;
    size_t indirect_blocks_needed = DIV_ROUND_UP (remaining_sectors, 128);
    
    for (size_t i = 0; i < indirect_blocks_needed && i < 128; i++) {
      if (d_indirect.indirect[i] != 0) {
        struct indirect_block indirect;
        block_read (fs_device, d_indirect.indirect[i], &indirect);
        
        size_t sectors_in_block = remaining_sectors > 128 ? 128 : remaining_sectors;
        for (size_t j = 0; j < sectors_in_block; j++) {
          if (indirect.direct[j] != 0) {
            free_map_release (indirect.direct[j], 1);
          }
        }
        free_map_release (d_indirect.indirect[i], 1);
        remaining_sectors -= sectors_in_block;
      }
    }
    free_map_release (disk_inode->double_indirect, 1);
  }
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir ? 1 : 0;
      
      memset (disk_inode->direct, 0, sizeof disk_inode->direct);
      disk_inode->indirect = 0;
      disk_inode->double_indirect = 0;
      
      success = true;
      static char zeros[BLOCK_SECTOR_SIZE];
      for (size_t i = 0; i < sectors; i++)
        {
          block_sector_t sector_num = get_or_allocate_sector (disk_inode, i);
          if (sector_num == 0)
            {
              success = false;
              break;
            }
          block_write (fs_device, sector_num, zeros);
        }
      
      if (success)
        {
          block_write (fs_device, sector, disk_inode);
        }
      else
        {
          free_inode_blocks (disk_inode);
        }
      
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;
  lock_acquire (&inode_list_lock);
  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          lock_release (&inode_list_lock);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_release (&inode_list_lock);
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init (&inode->inode_lock);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  lock_acquire (&inode->inode_lock);
  if (--inode->open_cnt == 0)
    {
      block_write (fs_device, inode->sector, &inode->data);
      
      /* Remove from inode list. */
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);
          free_inode_blocks (&inode->data);
        }

      lock_release (&inode->inode_lock);
      free (inode);
    }
  else
    {
      lock_release (&inode->inode_lock);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size,
                     off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  lock_acquire (&inode->inode_lock);

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);
  lock_release (&inode->inode_lock);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if an error occurs.
   Extends the file if writing past EOF. */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                      off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;
  
  off_t new_length = offset + size;
  lock_acquire (&inode->inode_lock);
  if (new_length > inode->data.length)
    {
      off_t old_length = inode->data.length;
      
      size_t old_sectors = bytes_to_sectors (old_length);
      size_t new_sectors = bytes_to_sectors (new_length);
      
      for (size_t i = old_sectors; i < new_sectors; i++)
        {
          block_sector_t sector_num = get_or_allocate_sector (&inode->data, i);
          if (sector_num == 0)
            {
              inode->data.length = old_sectors * BLOCK_SECTOR_SIZE;
              block_write (fs_device, inode->sector, &inode->data);
              return bytes_written;
            }
          
          static char zeros[BLOCK_SECTOR_SIZE];
          block_write (fs_device, sector_num, zeros);
        }
      
      inode->data.length = new_length;
      block_write (fs_device, inode->sector, &inode->data);
      
      if (offset > old_length)
        {
          off_t gap_start = old_length;
          off_t gap_end = offset;
          
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
            }
          
          if (gap_start % BLOCK_SECTOR_SIZE != 0)
            {
              size_t sector_idx = gap_start / BLOCK_SECTOR_SIZE;
              int sector_ofs = gap_start % BLOCK_SECTOR_SIZE;
              block_sector_t sector_num = get_or_allocate_sector (&inode->data, sector_idx);
              
              if (sector_num != 0 && bounce != NULL)
                {
                  block_read (fs_device, sector_num, bounce);
                  memset (bounce + sector_ofs, 0, BLOCK_SECTOR_SIZE - sector_ofs);
                  block_write (fs_device, sector_num, bounce);
                }
            }
          
          for (off_t pos = ROUND_UP (gap_start, BLOCK_SECTOR_SIZE); 
               pos < gap_end; 
               pos += BLOCK_SECTOR_SIZE)
            {
              size_t sector_idx = pos / BLOCK_SECTOR_SIZE;
              block_sector_t sector_num = get_or_allocate_sector (&inode->data, sector_idx);
              if (sector_num != 0)
                {
                  static char zeros[BLOCK_SECTOR_SIZE];
                  block_write (fs_device, sector_num, zeros);
                }
            }
        }
    }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      size_t sector_idx = offset / BLOCK_SECTOR_SIZE;
      block_sector_t sector_num = get_or_allocate_sector (&inode->data, sector_idx);
      if (sector_num == 0)
        break;
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_num, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            block_read (fs_device, sector_num, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_num, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  
  if (bytes_written > 0)
    {
      block_write (fs_device, inode->sector, &inode->data);
    }
  
  free (bounce);
  lock_release (&inode->inode_lock);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode)
{
  lock_acquire (&inode->inode_lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release (&inode->inode_lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode)

{
  lock_acquire (&inode->inode_lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release (&inode->inode_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode) { return inode->data.length; }

bool is_inode_dir(struct inode *inode) {
  if (inode == NULL)
    return false;
  lock_acquire (&inode->inode_lock);
  bool result = inode->data.is_dir != 0;
  lock_release (&inode->inode_lock);
  return result;
}

bool inode_is_removed (struct inode *inode) {
  if (inode == NULL)
    return false;
  lock_acquire (&inode->inode_lock);
  bool removed = inode->removed;
  lock_release (&inode->inode_lock);
  return removed;
}

int inode_get_open_cnt (const struct inode *inode) {
  return inode->open_cnt;
}
