/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;

namespace SMBLibrary
{
    public partial class NTFileStoreHelper
    {
        public static FileAccess ToCreateFileAccess(AccessMask desiredAccess, CreateDisposition createDisposition)
        {
            FileAccess result = 0;

            if (((FileAccessMask)desiredAccess & FileAccessMask.FILE_READ_DATA) > 0 ||
                ((FileAccessMask)desiredAccess & FileAccessMask.FILE_READ_EA) > 0 ||
                ((FileAccessMask)desiredAccess & FileAccessMask.FILE_READ_ATTRIBUTES) > 0 ||
                (desiredAccess & AccessMask.MAXIMUM_ALLOWED) > 0 ||
                (desiredAccess & AccessMask.GENERIC_ALL) > 0 ||
                (desiredAccess & AccessMask.GENERIC_READ) > 0)
            {
                result |= FileAccess.Read;
            }

            if (((FileAccessMask)desiredAccess & FileAccessMask.FILE_WRITE_DATA) > 0 ||
                ((FileAccessMask)desiredAccess & FileAccessMask.FILE_APPEND_DATA) > 0 ||
                ((FileAccessMask)desiredAccess & FileAccessMask.FILE_WRITE_EA) > 0 ||
                ((FileAccessMask)desiredAccess & FileAccessMask.FILE_WRITE_ATTRIBUTES) > 0 ||
                (desiredAccess & AccessMask.DELETE) > 0 ||
                (desiredAccess & AccessMask.WRITE_DAC) > 0 ||
                (desiredAccess & AccessMask.WRITE_OWNER) > 0 ||
                (desiredAccess & AccessMask.MAXIMUM_ALLOWED) > 0 ||
                (desiredAccess & AccessMask.GENERIC_ALL) > 0 ||
                (desiredAccess & AccessMask.GENERIC_WRITE) > 0)
            {
                result |= FileAccess.Write;
            }

            if (((DirectoryAccessMask)desiredAccess & DirectoryAccessMask.FILE_DELETE_CHILD) > 0)
            {
                result |= FileAccess.Write;
            }

            // Technically, FILE_OPEN_IF should only require Write access if the file does not exist,
            // However, It's uncommon for a client to open a file with FILE_OPEN_IF
            // without requesting any kind of write access in the access mask.
            // (because [if the file does not exist] an empty file will be created without the ability to write data to the file).
            if (createDisposition == CreateDisposition.FILE_CREATE ||
                createDisposition == CreateDisposition.FILE_SUPERSEDE ||
                createDisposition == CreateDisposition.FILE_OPEN_IF ||
                createDisposition == CreateDisposition.FILE_OVERWRITE ||
                createDisposition == CreateDisposition.FILE_OVERWRITE_IF)
            {
                result |= FileAccess.Write;
            }

            return result;
        }

        /// <summary>
        /// Will return desired FileAccess rights to the file data.
        /// </summary>
        public static FileAccess ToFileAccess(AccessMask desiredAccess)
        {
            return ToFileAccess((FileAccessMask)desiredAccess);
        }

        /// <summary>
        /// Will return desired FileAccess rights to the file data.
        /// </summary>
        public static FileAccess ToFileAccess(FileAccessMask desiredAccess)
        {
            FileAccess result = 0;
            if ((desiredAccess & FileAccessMask.FILE_READ_DATA) > 0 ||
                (desiredAccess & FileAccessMask.MAXIMUM_ALLOWED) > 0 ||
                (desiredAccess & FileAccessMask.GENERIC_ALL) > 0 ||
                (desiredAccess & FileAccessMask.GENERIC_READ) > 0)
            {
                result |= FileAccess.Read;
            }

            if ((desiredAccess & FileAccessMask.FILE_WRITE_DATA) > 0 ||
                (desiredAccess & FileAccessMask.FILE_APPEND_DATA) > 0 ||
                (desiredAccess & FileAccessMask.MAXIMUM_ALLOWED) > 0 ||
                (desiredAccess & FileAccessMask.GENERIC_ALL) > 0 ||
                (desiredAccess & FileAccessMask.GENERIC_WRITE) > 0)
            {
                result |= FileAccess.Write;
            }

            return result;
        }

        public static FileShare ToFileShare(ShareAccess shareAccess)
        {
            FileShare result = FileShare.None;
            if ((shareAccess & ShareAccess.Read) > 0)
            {
                result |= FileShare.Read;
            }

            if ((shareAccess & ShareAccess.Write) > 0)
            {
                result |= FileShare.Write;
            }

            if ((shareAccess & ShareAccess.Delete) > 0)
            {
                result |= FileShare.Delete;
            }

            return result;
        }

        public static FileNetworkOpenInformation GetNetworkOpenInformation(INTFileStore fileStore, string path, SecurityContext securityContext)
        {
            object handle;
            FileStatus fileStatus;
            NTStatus openStatus = fileStore.CreateFile(out handle, out fileStatus, path, (AccessMask)FileAccessMask.FILE_READ_ATTRIBUTES, 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, securityContext);
            if (openStatus != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            FileInformation fileInfo;
            NTStatus queryStatus = fileStore.GetFileInformation(out fileInfo, handle, FileInformationClass.FileNetworkOpenInformation);
            fileStore.CloseFile(handle);
            if (queryStatus != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }
            return (FileNetworkOpenInformation)fileInfo;
        }

        public static FileNetworkOpenInformation GetNetworkOpenInformation(INTFileStore fileStore, object handle)
        {
            FileInformation fileInfo;
            NTStatus status = fileStore.GetFileInformation(out fileInfo, handle, FileInformationClass.FileNetworkOpenInformation);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return null;
            }

            return (FileNetworkOpenInformation)fileInfo;
        }
    }
}