/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;

namespace SMBLibrary
{
    public delegate void OnNotifyChangeCompleted(NTStatus status, byte[] buffer, object context);

    /// <summary>
    /// A file store (a.k.a. object store) interface to allow access to a file system or a named pipe in an NT-like manner dictated by the SMB protocol.
    /// </summary>
    public interface INTFileStore
    {
        NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext);

        NTStatus CloseFile(object handle);

        NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount);

        NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data);

        NTStatus FlushFileBuffers(object handle);

        NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock);

        NTStatus UnlockFile(object handle, long byteOffset, long length);

        NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object handle, string fileName, FileInformationClass informationClass);

        NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass);

        NTStatus SetFileInformation(object handle, FileInformation information);

        NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass);

        NTStatus SetFileSystemInformation(FileSystemInformation information);

        NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation);

        NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor);

        /// <summary>
        /// Monitor the contents of a directory (and its subdirectories) by using change notifications.
        /// When something changes within the directory being watched this operation is completed.
        /// </summary>
        /// <returns>
        /// STATUS_PENDING - The directory is being watched, change notification will be provided using callback method.
        /// STATUS_NOT_SUPPORTED - The underlying object store does not support change notifications.
        /// STATUS_INVALID_HANDLE - The handle supplied is invalid.
        /// </returns>
        NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context);

        NTStatus Cancel(object ioRequest);

        NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength);
    }
}