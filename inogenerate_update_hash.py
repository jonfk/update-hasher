#!/usr/bin/python

import os
import json
import sys, getopt
import subprocess

import base64
import hashlib

UPDATE_FILE = 'update.gz'
METADATA_FILE = 'update.meta'

SHA1_ATTR = 'sha1'
SHA256_ATTR = 'sha256'
SIZE_ATTR = 'size'
ISDELTA_ATTR = 'is_delta'

#payload_dir = '.'

_HASH_BLOCK_SIZE = 8192

devkey = "/usr/share/update_engine/update-payload-key.key.pem"

private_key = devkey

src_image = ''

### Hashing Functions

class AutoupdateError(Exception):
    """Exception classes used by this module."""
    pass

class UpdateMetadata(object):
    """Object containing metadata about an update payload."""

    def __init__(self, sha1, sha256, size, is_delta_format):
        self.sha1 = sha1
        self.sha256 = sha256
        self.size = size
        self.is_delta_format = is_delta_format

def GetLocalPayloadAttrs(payload_dir):
    """Returns hashes, size and delta flag of a local update payload.

    Args:
      payload_dir: Path to the directory the payload is in.
    Returns:
      A tuple containing the SHA1, SHA256, file size and whether or not it's a
      delta payload (Boolean).
    """
    filename = os.path.join(payload_dir, UPDATE_FILE)
    if not os.path.exists(filename):
        raise AutoupdateError('update.gz not present in payload dir %s' %
                              payload_dir)

    sha1 = GetFileSha1(filename)
    sha256 = GetFileSha256(filename)
    size = GetFileSize(filename)
    #is_delta_format = self._IsDeltaFormatFile(filename)
    is_delta_format = True
    metadata_obj = UpdateMetadata(sha1, sha256, size, is_delta_format)
    _StoreMetadataToFile(payload_dir, metadata_obj)

    return metadata_obj

def _StoreMetadataToFile(payload_dir, metadata_obj):
    """Stores metadata object into the metadata_file of the payload_dir"""
    file_dict = {SHA1_ATTR: metadata_obj.sha1,
                 SHA256_ATTR: metadata_obj.sha256,
                 SIZE_ATTR: metadata_obj.size,
                 ISDELTA_ATTR: metadata_obj.is_delta_format}
    metadata_file = os.path.join(payload_dir, METADATA_FILE)
    with open(metadata_file, 'w') as file_handle:
        json.dump(file_dict, file_handle)


def GetFileSize(file_path):
    """Returns the size in bytes of the file given."""
    return os.path.getsize(file_path)


# Hashlib is strange and doesn't actually define these in a sane way that
# pylint can find them. Disable checks for them.
# pylint: disable=E1101,W0106
def GetFileHashes(file_path, do_sha1=False, do_sha256=False, do_md5=False):
    """Computes and returns a list of requested hashes.

    Args:
      file_path: path to file to be hashed
      do_sha1:   whether or not to compute a SHA1 hash
      do_sha256: whether or not to compute a SHA256 hash
      do_md5:    whether or not to compute a MD5 hash
    Returns:
      A dictionary containing binary hash values, keyed by 'sha1', 'sha256' and
      'md5', respectively.
    """
    hashes = {}
    if (do_sha1 or do_sha256 or do_md5):
        # Initialize hashers.
        hasher_sha1 = hashlib.sha1() if do_sha1 else None
        hasher_sha256 = hashlib.sha256() if do_sha256 else None
        hasher_md5 = hashlib.md5() if do_md5 else None

        # Read blocks from file, update hashes.
        with open(file_path, 'rb') as fd:
            while True:
                block = fd.read(_HASH_BLOCK_SIZE)
                if not block:
                    break
                hasher_sha1 and hasher_sha1.update(block)
                hasher_sha256 and hasher_sha256.update(block)
                hasher_md5 and hasher_md5.update(block)

        # Update return values.
        if hasher_sha1:
            hashes['sha1'] = hasher_sha1.digest()
        if hasher_sha256:
            hashes['sha256'] = hasher_sha256.digest()
        if hasher_md5:
            hashes['md5'] = hasher_md5.digest()

    return hashes


def GetFileSha1(file_path):
    """Returns the SHA1 checksum of the file given (base64 encoded)."""
    return base64.b64encode(GetFileHashes(file_path, do_sha1=True)['sha1'])


def GetFileSha256(file_path):
    """Returns the SHA256 checksum of the file given (base64 encoded)."""
    return base64.b64encode(GetFileHashes(file_path, do_sha256=True)['sha256'])


def GetFileMd5(file_path):
    """Returns the MD5 checksum of the file given (hex encoded)."""
    return binascii.hexlify(GetFileHashes(file_path, do_md5=True)['md5'])

### Generating update functions
def GenerateUpdateFile(src_image, image_path, output_dir):
    """Generates an update gz given a full path to an image.

    Args:
      image_path: Full path to image.
    Raises:
      subprocess.CalledProcessError if the update generator fails to generate a
      stateful payload.
    """
    update_path = os.path.join(output_dir, UPDATE_FILE)
    print 'Generating update image %s'.format(update_path)

    update_command = [
        'cros_generate_update_payload',
        '--image', image_path,
        '--output', update_path,
    ]

    if src_image:
        update_command.extend(['--src_image', src_image])

    if private_key:
        update_command.extend(['--private_key', private_key])

    print 'Running %s'.format(' '.join(update_command))
    subprocess.check_call(update_command)

def GenerateUpdateImage(image_path, output_dir):
    """Force generates an update payload based on the given image_path.

    Args:
      src_image: image we are updating from (Null/empty for non-delta)
      image_path: full path to the image.
      output_dir: the directory to write the update payloads to
    Raises:
      AutoupdateError if it failed to generate either update or stateful
        payload.
    """
    print 'Generating update for image %s'.format(image_path)

    # Delete any previous state in this directory.
    os.system('rm -rf "%s"' % output_dir)
    os.makedirs(output_dir)

    try:
        GenerateUpdateFile(src_image, image_path, output_dir)
    except subprocess.CalledProcessError:
        os.system('rm -rf "%s"' % output_dir)
        raise AutoupdateError('Failed to generate update in %s' % output_dir)


def main(argv):
    image_dir = ''
    image_name = 'coreos_production_image.bin'
    try:
        opts, args = getopt.getopt(argv, "d:i:", ["dir=","image="])
    except getopt.GetoptError:
        print 'inogenerate_update_hash.py -d <directoryimage> -i <imagefilename>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'inogenerate_update_hash.py -d <directoryimage> -i <imagefilename>\ne.g:\n\t inogenerate_update_hash.py -d ../build/images/amd64-usr/alpha-452.0.0+2014-10-21-1913-a1 -i coreos_production_image.bin'
            sys.exit()
        elif opt in ("-d", "--dir"):
            image_dir = arg
        elif opt in ("-i", "--image"):
            image_name = arg

    if image_dir == '':
        print 'Please specify the image directory'
        print 'inogenerate_update_hash.py -d <directoryimage> -i <imagefilename>\ne.g:\n\t inogenerate_update_hash.py -d ../build/images/amd64-usr/alpha-452.0.0+2014-10-21-1913-a1 -i coreos_production_image.bin'
        sys.exit()
    image_path = os.path.join(image_dir, image_name)
    output_dir = os.path.join(image_dir, 'payload')
    GenerateUpdateImage(image_path, output_dir)

    GetLocalPayloadAttrs(output_dir)

if __name__ == "__main__":
    main(sys.argv[1:])
