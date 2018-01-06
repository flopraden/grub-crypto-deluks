/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2007,2010,2011  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/cryptodisk.h>
#include <grub/types.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/err.h>
#include <grub/disk.h>
#include <grub/file.h>
#include <grub/crypto.h>
#include <grub/partition.h>
#include <grub/i18n.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define LUKS_KEY_ENABLED  0x00AC71F3

/* On disk LUKS header */
struct grub_luks_phdr
{
  grub_uint8_t magic[6];
#define LUKS_MAGIC        "LUKS\xBA\xBE"
  grub_uint16_t version;
  char cipherName[32];
  char cipherMode[32];
  char hashSpec[32];
  grub_uint32_t payloadOffset;
  grub_uint32_t keyBytes;
  grub_uint8_t mkDigest[20];
  grub_uint8_t mkDigestSalt[32];
  grub_uint32_t mkDigestIterations;
  char uuid[40];
  struct
  {
    grub_uint32_t active;
    grub_uint32_t passwordIterations;
    grub_uint8_t passwordSalt[32];
    grub_uint32_t keyMaterialOffset;
    grub_uint32_t stripes;
  } keyblock[8];
} GRUB_PACKED;

/* Deniable LUKS options header */
struct deluks_phdr_opt {          // ENCRYPTED ON DISK
  char    magic[6];
  grub_uint16_t  version;
  grub_uint32_t  keyBytes;
  char    cipherName[32];
  char    cipherMode[32];
  grub_uint64_t  payloadOffset;
  grub_uint64_t  payloadTotalSectors;
  char    uuid[40];
  grub_uint8_t   bootPriority;
  struct GRUB_PACKED {
    grub_uint32_t active;
  } keyblock[8];
  grub_uint8_t   _padding[347];
} GRUB_PACKED;

/* On disk Deniable LUKS header */
struct grub_deluks_phdr
{
  grub_uint8_t magic[6];             // RANDOM ON DISK
  grub_uint16_t version;             // RANDOM ON DISK
  char cipherName[32];               // RANDOM ON DISK
  char cipherMode[32];               // RANDOM ON DISK
  char hashSpec[32];                 // RANDOM ON DISK
  grub_uint64_t payloadOffset;       // RANDOM ON DISK
  grub_uint32_t keyBytes;            // RANDOM ON DISK
  grub_uint8_t mkDigest[20];
  grub_uint8_t mkDigestSalt[32];
  grub_uint32_t mkDigestIterations;  // RANDOM ON DISK
  char uuid[40];                     // RANDOM ON DISK
  grub_uint8_t _padding1[300]; /* Have specialPadding10 instead of keyblock[3] salt at the position of Master Boot Record magic number */

  /* key information blocks, 512 bytes */
  struct GRUB_PACKED
  {
    grub_uint32_t active;
    grub_uint32_t passwordIterations;
    grub_uint8_t passwordSalt[32];
    grub_uint64_t keyMaterialOffset;
    grub_uint32_t stripes;
  } keyblock[8];
  grub_uint8_t additionalPadding15[96]; /* Start on new sector */

  /* encrypted part, 512 bytes */
  struct deluks_phdr_opt options;
} GRUB_PACKED;


typedef struct grub_luks_phdr *grub_luks_phdr_t;

gcry_err_code_t AF_merge (const gcry_md_spec_t * hash, grub_uint8_t * src,
			  grub_uint8_t * dst, grub_size_t blocksize,
			  grub_size_t blocknumbers);
 
// LUKS
static grub_cryptodisk_t
configure_ciphers (grub_disk_t disk, const char *check_uuid,
		   int check_boot, grub_file_t hdr)
{
  grub_cryptodisk_t newdev;
  struct grub_luks_phdr header;
  char uuid[sizeof (header.uuid) + 1];
  char ciphername[sizeof (header.cipherName) + 1];
  char ciphermode[sizeof (header.cipherMode) + 1];
  char hashspec[sizeof (header.hashSpec) + 1];
  grub_err_t err;

  err = GRUB_ERR_NONE;

  if (check_boot)
    return NULL;

  /* Read the LUKS header.  */
  if (hdr)
  {
    grub_file_seek (hdr, 0);
    if (grub_file_read (hdr, &header, sizeof (header)) != sizeof (header))
        err = GRUB_ERR_READ_ERROR;
  }
  else
    err = grub_disk_read (disk, 0, 0, sizeof (header), &header);

  if (err)
    {
      if (err == GRUB_ERR_OUT_OF_RANGE)
	grub_errno = GRUB_ERR_NONE;
      return NULL;
    }

  /* Look for LUKS magic sequence.  */
  if (grub_memcmp (header.magic, LUKS_MAGIC, sizeof (header.magic))
      || grub_be_to_cpu16 (header.version) != 1)
    return NULL;

  /* Make sure that strings are null terminated.  */
  grub_memcpy (ciphername, header.cipherName, sizeof (header.cipherName));
  ciphername[sizeof (header.cipherName)] = 0;
  grub_memcpy (ciphermode, header.cipherMode, sizeof (header.cipherMode));
  ciphermode[sizeof (header.cipherMode)] = 0;
  grub_memcpy (hashspec, header.hashSpec, sizeof (header.hashSpec));
  hashspec[sizeof (header.hashSpec)] = 0;
  grub_memcpy (uuid, header.uuid, sizeof (header.uuid));
  uuid[sizeof (header.uuid)] = 0;

  if ( check_uuid && ! grub_cryptodisk_uuidcmp(check_uuid, uuid))
    {
      grub_dprintf ("luks", "%s != %s\n", uuid, check_uuid);
      return NULL;
    }

  newdev = grub_cryptodisk_create (disk, NULL, ciphername, ciphermode, hashspec);

  newdev->offset = grub_be_to_cpu32 (2097151/GRUB_DISK_SECTOR_SIZE+1); // Offset will be at least at 4096*512 bytes (LUKS/DELUKS header size) whatever the newer disk sector sizes (GRUB constant??)
  newdev->modname = "luks";

  return newdev;
}

// LUKS
static grub_err_t
luks_recover_key (grub_disk_t source,
                  grub_cryptodisk_t dev,
                  grub_file_t hdr,
                  grub_uint8_t *keyfile_bytes,
                  grub_size_t keyfile_bytes_size)
{
  struct grub_luks_phdr header;
  grub_size_t keysize;
  grub_uint8_t *split_key = NULL;
  char interactive_passphrase[GRUB_CRYPTODISK_MAX_PASSPHRASE] = "";
  grub_uint8_t *passphrase;
  grub_size_t passphrase_length;
  grub_uint8_t candidate_digest[sizeof (header.mkDigest)];
  unsigned i;
  grub_size_t length;
  grub_err_t err;
  grub_size_t max_stripes = 1;
  char *tmp;
  grub_uint32_t sector;
  unsigned attempts = 2;

  err = GRUB_ERR_NONE;

  if (hdr)
  {
    grub_file_seek (hdr, 0);
    if (grub_file_read (hdr, &header, sizeof (header)) != sizeof (header))
        err = GRUB_ERR_READ_ERROR;
  }
  else
    err = grub_disk_read (source, 0, 0, sizeof (header), &header);

  if (err)
    return err;

  grub_puts_ (N_("Attempting to decrypt LUKS master key..."));
  keysize = grub_be_to_cpu32 (header.keyBytes);
  if (keysize > GRUB_CRYPTODISK_MAX_KEYLEN)
    return grub_error (GRUB_ERR_BAD_FS, "key is too long");

  for (i = 0; i < ARRAY_SIZE (header.keyblock); i++)
    if (grub_be_to_cpu32 (header.keyblock[i].active) == LUKS_KEY_ENABLED
        && grub_be_to_cpu32 (header.keyblock[i].stripes) > max_stripes)
      max_stripes = grub_be_to_cpu32 (header.keyblock[i].stripes);

  split_key = grub_malloc (keysize * max_stripes);
  if (!split_key)
    return grub_errno;

  while (attempts)
    {
      if (keyfile_bytes)
        {
          /* Use bytestring from key file as passphrase */
          passphrase = keyfile_bytes;
          passphrase_length = keyfile_bytes_size;
          keyfile_bytes = NULL; /* use it only once */
        }
      else
        {
          /* Get the passphrase from the user.  */
          tmp = NULL;
          if (source->partition)
            tmp = grub_partition_get_name (source->partition);
          grub_printf_ (N_("Enter passphrase for %s%s%s (%s): "), source->name,
                              source->partition ? "," : "", tmp ? : "", dev->uuid);
          grub_free (tmp);
          if (!grub_password_get (interactive_passphrase, GRUB_CRYPTODISK_MAX_PASSPHRASE))
            {
              grub_free (split_key);
              return grub_error (GRUB_ERR_BAD_ARGUMENT, "Passphrase not supplied");
            }

          passphrase = (grub_uint8_t *)interactive_passphrase;
          passphrase_length = grub_strlen (interactive_passphrase);

        }

      /* Try to recover master key from each active keyslot.  */
      for (i = 0; i < ARRAY_SIZE (header.keyblock); i++)
        {
          gcry_err_code_t gcry_err;
          grub_uint8_t candidate_key[GRUB_CRYPTODISK_MAX_KEYLEN];
          grub_uint8_t digest[GRUB_CRYPTODISK_MAX_KEYLEN];

          /* Check if keyslot is enabled.  */
          if (grub_be_to_cpu32 (header.keyblock[i].active) != LUKS_KEY_ENABLED)
            continue;

          grub_dprintf ("luks", "Trying keyslot %d\n", i);

          /* Calculate the PBKDF2 of the user supplied passphrase.  */
          gcry_err = grub_crypto_pbkdf2 (dev->hash, (grub_uint8_t *) passphrase,
                                         passphrase_length,
                                         header.keyblock[i].passwordSalt,
                                         sizeof (header.keyblock[i].passwordSalt),
                                         grub_be_to_cpu32 (header.keyblock[i].
                                         passwordIterations),
                                         digest, keysize);

          if (gcry_err)
            {
              grub_free (split_key);
              return grub_crypto_gcry_error (gcry_err);
            }

          grub_dprintf ("luks", "PBKDF2 done\n");

          gcry_err = grub_cryptodisk_setkey (dev, digest, keysize);
          if (gcry_err)
            {
              grub_free (split_key);
              return grub_crypto_gcry_error (gcry_err);
            }

          sector = grub_be_to_cpu32 (header.keyblock[i].keyMaterialOffset);
          length = (keysize * grub_be_to_cpu32 (header.keyblock[i].stripes));

          /* Read and decrypt the key material from the disk.  */
          if (hdr)
            {
              grub_file_seek (hdr, sector * 512);
              if (grub_file_read (hdr, split_key, length) != (grub_ssize_t)length)
                err = GRUB_ERR_READ_ERROR;
            }
          else
            err = grub_disk_read (source, sector, 0, length, split_key);
          if (err)
            {
              grub_free (split_key);
              return err;
            }

          gcry_err = grub_cryptodisk_decrypt (dev, split_key, length, 0);
          if (gcry_err)
            {
              grub_free (split_key);
              return grub_crypto_gcry_error (gcry_err);
            }

          /* Merge the decrypted key material to get the candidate master key.  */
          gcry_err = AF_merge (dev->hash, split_key, candidate_key, keysize,
                               grub_be_to_cpu32 (header.keyblock[i].stripes));
          if (gcry_err)
            {
              grub_free (split_key);
              return grub_crypto_gcry_error (gcry_err);
            }

          grub_dprintf ("luks", "candidate key recovered\n");

          /* Calculate the PBKDF2 of the candidate master key.  */
          gcry_err = grub_crypto_pbkdf2 (dev->hash, candidate_key,
                                     grub_be_to_cpu32 (header.keyBytes),
                                     header.mkDigestSalt,
                                     sizeof (header.mkDigestSalt),
                                     grub_be_to_cpu32
                                     (header.mkDigestIterations),
                                     candidate_digest,
                                     sizeof (candidate_digest));
          if (gcry_err)
            {
              grub_free (split_key);
              return grub_crypto_gcry_error (gcry_err);
            }

          /* Compare the calculated PBKDF2 to the digest stored
             in the header to see if it's correct.  */
          if (grub_memcmp (candidate_digest, header.mkDigest,
                                             sizeof (header.mkDigest)) != 0)
            {
              grub_dprintf ("luks", "bad digest\n");
              continue;
            }

          /* TRANSLATORS: It's a cryptographic key slot: one element of an array
             where each element is either empty or holds a key.  */
          grub_printf_ (N_("Slot %d opened\n"), i);

          /* Set the master key.  */
          gcry_err = grub_cryptodisk_setkey (dev, candidate_key, keysize);
          if (gcry_err)
            {
              grub_free (split_key);
              return grub_crypto_gcry_error (gcry_err);
            }

          grub_free (split_key);

          return GRUB_ERR_NONE;
        }
      grub_printf_ (N_("Failed to decrypt master key.\n"));
      if (--attempts) grub_printf_ (N_("%u attempt%s remaining.\n"), attempts,
                        (attempts==1) ? "" : "s");
    }

  grub_free (split_key);
  return GRUB_ACCESS_DENIED;
}

// DELUKS

// DELUKS
static grub_cryptodisk_t
scan_recover_deluks (grub_disk_t source,
                    grub_disk_addr_t start_sector,
                    const char *check_uuid __attribute__ ((unused)),
                    int check_boot,
                    grub_file_t hdr,
                    grub_uint8_t *keyfile_bytes,
                    grub_size_t keyfile_bytes_size,
                    char (*interactive_passphrase)[GRUB_CRYPTODISK_MAX_PASSPHRASE])
{
  grub_cryptodisk_t dev_keys, dev_opts;
  grub_cryptodisk_t dev;
  struct grub_luks_phdr header;
  struct grub_deluks_phdr header_deluks;
  char uuid[sizeof (header.uuid) + 1];
  char ciphername[sizeof (header.cipherName) + 1];
  char ciphermode[sizeof (header.cipherMode) + 1];
  char hashspec[sizeof (header.hashSpec) + 1];
  grub_err_t err;
  grub_size_t keysize;
  grub_uint8_t *split_key = NULL;
  grub_uint8_t *passphrase;
  grub_size_t passphrase_length;
  grub_uint8_t candidate_digest[sizeof (header.mkDigest)];
  unsigned i;
  grub_size_t length;
  grub_uint32_t sector;
  char ciphermode_enc_hdr[]="xts-plain64";
  //char* ciphermode_opts;

  err = GRUB_ERR_NONE;
  if (check_boot)
    return NULL;

  /* Read the DeLUKS header.  */
  if (hdr)
  {
    /* Detached DeLUKS header is supported. */
    /* Detached "Plain" LUKS header is not supported for now. */
    grub_file_seek (hdr, 0);
    if (grub_file_read (hdr, &header_deluks, sizeof (header_deluks)) != sizeof (header_deluks))
        err = GRUB_ERR_READ_ERROR;
  }
  else
    err = grub_disk_read (source, start_sector, 0, sizeof (header_deluks), &header_deluks);

  if (err)
    {
      if (err == GRUB_ERR_OUT_OF_RANGE)
        grub_errno = GRUB_ERR_NONE;
      return NULL;
    }


  /* Make sure that strings are null terminated.  */
  grub_memcpy (ciphername, GRUB_CRYPTODISK_DENIABLE_CIPHERNAME, sizeof (header.cipherName));
  ciphername[sizeof (GRUB_CRYPTODISK_DENIABLE_CIPHERNAME)] = 0;
  grub_memcpy (ciphermode, GRUB_CRYPTODISK_DENIABLE_CIPHERMODE, sizeof (header.cipherMode)); // TODO: should be parameterizable from command-line for onward compatibility/security
  ciphermode[sizeof (GRUB_CRYPTODISK_DENIABLE_CIPHERMODE)] = 0;
  grub_memcpy (hashspec, GRUB_CRYPTODISK_DENIABLE_DIGEST, sizeof (header.hashSpec));
  hashspec[sizeof (GRUB_CRYPTODISK_DENIABLE_DIGEST)] = 0;
  grub_memcpy (uuid, "\0", sizeof (header.uuid));
  /* UUID is inside encrypted options
  if ( check_uuid && ! grub_cryptodisk_uuidcmp(check_uuid, uuid))
    {
      grub_dprintf ("luks", "%s != %s\n", uuid, check_uuid);
      return NULL;
    }
  */

  dev_keys = grub_cryptodisk_create (source, uuid, ciphername, ciphermode, hashspec);
  dev_keys->offset = 4096; // Temporary until we decrypt the header
  dev_keys->modname = "luks";

  err = GRUB_ERR_NONE;

  if (hdr)
  {
    grub_file_seek (hdr, 0);
    if (grub_file_read (hdr, &header_deluks, sizeof (header_deluks)) != sizeof (header_deluks))
        err = GRUB_ERR_READ_ERROR;
  }
  else
    err = grub_disk_read (source, start_sector, 0, sizeof (header_deluks), &header_deluks);

  if (err) {
    grub_errno = err;
    cryptodisk_close (dev_keys);
    return NULL;
  }

  grub_puts_ (N_("Attempting to decrypt DeLUKS master key..."));

  keysize = GRUB_CRYPTODISK_DENIABLE_KEYSIZE;
  if (keysize > GRUB_CRYPTODISK_MAX_KEYLEN) {
    grub_errno = grub_error (GRUB_ERR_BAD_FS, "key is too long");
    cryptodisk_close (dev_keys);
    return NULL;
  }

  split_key = grub_malloc (GRUB_CRYPTODISK_DENIABLE_KEYSIZE * GRUB_CRYPTODISK_DENIABLE_AF_STRIPES);
  if (!split_key) {
    cryptodisk_close (dev_keys);
    return NULL;
  }

      if (keyfile_bytes)
        {
          /* Use bytestring from key file as passphrase */
          passphrase = keyfile_bytes;
          passphrase_length = keyfile_bytes_size;
          keyfile_bytes = NULL; /* use it only once */
        }
      else
        {
          passphrase = (grub_uint8_t *)*interactive_passphrase;
          passphrase_length = grub_strlen (*interactive_passphrase);
        }

      /* Try to recover master key from each active keyslot.  */
      for (i = 0; i < 1; i++) // TEEEEMP => i < ARRAY_SIZE (header_deluks.keyblock)
        {
          gcry_err_code_t gcry_err;
          grub_uint8_t candidate_key[GRUB_CRYPTODISK_MAX_KEYLEN];
          grub_uint8_t digest[GRUB_CRYPTODISK_MAX_KEYLEN];

          // There is no deniable notion of enabled keyslot. All 8 slots are tested.

          grub_dprintf ("luks", "Trying keyslot %d\n", i);

          /* Calculate the PBKDF2 of the user supplied passphrase.  */
          gcry_err = grub_crypto_pbkdf2 (dev_keys->hash, (grub_uint8_t *) passphrase,
                                         passphrase_length,
                                         header_deluks.keyblock[i].passwordSalt,
                                         sizeof (header_deluks.keyblock[i].passwordSalt),
                                         GRUB_CRYPTODISK_DENIABLE_ITERATIONS,
                                         digest, keysize);

          if (gcry_err)
            {
              grub_free (split_key);
              grub_errno = grub_crypto_gcry_error (gcry_err);
              cryptodisk_close (dev_keys);
              return NULL;
            }

          gcry_err = grub_cryptodisk_setkey (dev_keys, digest, keysize);
          if (gcry_err)
            {
              grub_free (split_key);
              grub_errno = grub_crypto_gcry_error (gcry_err);
              cryptodisk_close (dev_keys);
              return NULL;
            }

          sector = start_sector + 8 + i*GRUB_CRYPTODISK_DENIABLE_KEYSIZE*GRUB_CRYPTODISK_DENIABLE_AF_STRIPES;
          length = (keysize * GRUB_CRYPTODISK_DENIABLE_AF_STRIPES);

          /* Read and decrypt the key material from the disk.  */
          if (hdr)
            {
              grub_file_seek (hdr, sector * GRUB_DISK_SECTOR_SIZE);
              if (grub_file_read (hdr, split_key, length) != (grub_ssize_t)length)
                err = GRUB_ERR_READ_ERROR;
            }
          else
            err = grub_disk_read (source, sector, 0, length, split_key);
          if (err)
            {
              grub_free (split_key);
              grub_errno = err;
              cryptodisk_close (dev_keys);
              return NULL;
            }

          gcry_err = grub_cryptodisk_decrypt (dev_keys, split_key, length, 0);
          if (gcry_err)
            {
              grub_free (split_key);
              grub_errno = grub_crypto_gcry_error (gcry_err);
              cryptodisk_close (dev_keys);
              return NULL;
            }

          /* Merge the decrypted key material to get the candidate master key.  */
          gcry_err = AF_merge (dev_keys->hash, split_key, candidate_key, keysize,
                               GRUB_CRYPTODISK_DENIABLE_AF_STRIPES);
          if (gcry_err)
            {
              grub_free (split_key);
              grub_errno = grub_crypto_gcry_error (gcry_err);
              cryptodisk_close (dev_keys);
              return NULL;
            }

          grub_dprintf ("luks", "candidate key recovered\n");

          /* Calculate the PBKDF2 of the candidate master key.  */
          gcry_err = grub_crypto_pbkdf2 (dev_keys->hash, candidate_key,
                                     GRUB_CRYPTODISK_DENIABLE_KEYSIZE,
                                     header_deluks.mkDigestSalt,
                                     sizeof (header_deluks.mkDigestSalt),
                                     GRUB_CRYPTODISK_DENIABLE_ITERATIONS,
                                     candidate_digest,
                                     sizeof (candidate_digest));
          if (gcry_err)
            {
              grub_free (split_key);
              grub_errno = grub_crypto_gcry_error (gcry_err);
              cryptodisk_close (dev_keys);
              return NULL;
            }

          /* Compare the calculated PBKDF2 to the digest stored
             in the header to see if it's correct.  */
          if (grub_memcmp (candidate_digest, header_deluks.mkDigest,
                                             sizeof (header_deluks.mkDigest)) != 0)
            {
              grub_dprintf ("luks", "bad digest\n");
              continue;
            }

          /* TRANSLATORS: It's a cryptographic key slot: one element of an array
             where each element is either empty or holds a key.  */
          grub_printf_ (N_("Slot %d opened\n"), i);


          /*  !!!!!!!!!!! TODO !!!!!!!!!
              Header encryption settings are stored in the cryptodevice struct.
              They will be replaced by the payload encryption seetings.

        
          Decipher options encrypted header. We need:
          - UUID
          - CipherName
          - CipherMode
          - Boot priority
          - Keybytes (trunk)
          - payloadOffset
          - payloadTotalSector


          Set all final header/device variables
          Device start offset?
          Fixed header size sector size independant

          */

          /* Decrypt the options sub-header */
          grub_dprintf ("luks", "starting header decryption\n");

          char  *buf_out = (char*)&header_deluks.options;

          dev_opts = grub_cryptodisk_create (source, uuid, ciphername, ciphermode_enc_hdr, hashspec);
          gcry_err = grub_cryptodisk_setkey (dev_opts, candidate_key, keysize);
          if (gcry_err)
            {
              grub_errno = grub_crypto_gcry_error (gcry_err);
              grub_free (split_key);
              cryptodisk_close (dev_keys);
              return NULL;
            }

          grub_cryptodisk_decrypt (dev_opts, (grub_uint8_t*) buf_out, sizeof(header_deluks.options), (grub_disk_addr_t) 0);
          grub_dprintf ("luks", "decrypted cipherName = %s\n", header_deluks.options.cipherName);

          /* Create the final device */
          dev = grub_cryptodisk_create (source, uuid, ciphername, ciphermode, hashspec);
          dev->offset = 4096; // Temporary until we decrypt the header
          dev->modname = "luks";

          /* Set the master key.  */
          gcry_err = grub_cryptodisk_setkey (dev, candidate_key, keysize);
          if (gcry_err)
            {
              grub_errno = grub_crypto_gcry_error (gcry_err);
              grub_free (split_key);
              cryptodisk_close (dev_keys);
              cryptodisk_close (dev);
              return NULL;
            }

          grub_free (split_key);

          cryptodisk_close (dev_keys);
          return dev;
        }
      grub_printf_ (N_("Failed to decrypt master key.\n"));
      // There is only one attempt to decrypt.
      // Other attempts should be implemented at the grub_cmd_cryptomount() level.

  grub_free (split_key);
  grub_errno = GRUB_ACCESS_DENIED;
  cryptodisk_close (dev_keys);
  return NULL;
}

struct grub_cryptodisk_dev luks_crypto = {
  .scan = configure_ciphers,
  .recover_key = luks_recover_key,
  .scan_recover_deluks = scan_recover_deluks
};

GRUB_MOD_INIT (luks)
{
  COMPILE_TIME_ASSERT (sizeof (((struct grub_luks_phdr *) 0)->uuid)
		       < GRUB_CRYPTODISK_MAX_UUID_LENGTH);
  grub_cryptodisk_dev_register (&luks_crypto);
}

GRUB_MOD_FINI (luks)
{
  grub_cryptodisk_dev_unregister (&luks_crypto);
}
