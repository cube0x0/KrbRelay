/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Services;
using System;
using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary
{
    public class NamedPipeStore : INTFileStore
    {
        private List<RemoteService> m_services;

        public NamedPipeStore(List<RemoteService> services)
        {
            m_services = services;
        }

        public NTStatus CreateFile(out object handle, out FileStatus fileStatus, string path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            // It is possible to have a named pipe that does not use RPC (e.g. MS-WSP),
            // However this is not currently needed by our implementation.
            RemoteService service = GetService(path);
            if (service != null)
            {
                // All instances of a named pipe share the same pipe name, but each instance has its own buffers and handles,
                // and provides a separate conduit for client/server communication.
                RPCPipeStream stream = new RPCPipeStream(service);
                handle = new FileHandle(path, false, stream, false);
                fileStatus = FileStatus.FILE_OPENED;
                return NTStatus.STATUS_SUCCESS;
            }
            handle = null;
            return NTStatus.STATUS_OBJECT_PATH_NOT_FOUND;
        }

        public NTStatus CloseFile(object handle)
        {
            FileHandle fileHandle = (FileHandle)handle;
            if (fileHandle.Stream != null)
            {
                fileHandle.Stream.Close();
            }
            return NTStatus.STATUS_SUCCESS;
        }

        private RemoteService GetService(string path)
        {
            if (path.StartsWith(@"\"))
            {
                path = path.Substring(1);
            }

            foreach (RemoteService service in m_services)
            {
                if (String.Equals(path, service.PipeName, StringComparison.OrdinalIgnoreCase))
                {
                    return service;
                }
            }
            return null;
        }

        public NTStatus ReadFile(out byte[] data, object handle, long offset, int maxCount)
        {
            Stream stream = ((FileHandle)handle).Stream;
            data = new byte[maxCount];
            int bytesRead = stream.Read(data, 0, maxCount);
            if (bytesRead < maxCount)
            {
                // EOF, we must trim the response data array
                data = ByteReader.ReadBytes(data, 0, bytesRead);
            }
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, byte[] data)
        {
            Stream stream = ((FileHandle)handle).Stream;
            stream.Write(data, 0, data.Length);
            numberOfBytesWritten = data.Length;
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus FlushFileBuffers(object handle)
        {
            FileHandle fileHandle = (FileHandle)handle;
            if (fileHandle.Stream != null)
            {
                fileHandle.Stream.Flush();
            }
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus DeviceIOControl(object handle, uint ctlCode, byte[] input, out byte[] output, int maxOutputLength)
        {
            output = null;
            if (ctlCode == (uint)IoControlCode.FSCTL_PIPE_WAIT)
            {
                PipeWaitRequest request;
                try
                {
                    request = new PipeWaitRequest(input, 0);
                }
                catch
                {
                    return NTStatus.STATUS_INVALID_PARAMETER;
                }

                RemoteService service = GetService(request.Name);
                if (service == null)
                {
                    return NTStatus.STATUS_OBJECT_NAME_NOT_FOUND;
                }

                output = new byte[0];
                return NTStatus.STATUS_SUCCESS;
            }
            else if (ctlCode == (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE)
            {
                int numberOfBytesWritten;
                NTStatus writeStatus = WriteFile(out numberOfBytesWritten, handle, 0, input);
                if (writeStatus != NTStatus.STATUS_SUCCESS)
                {
                    return writeStatus;
                }
                int messageLength = ((RPCPipeStream)((FileHandle)handle).Stream).MessageLength;
                NTStatus readStatus = ReadFile(out output, handle, 0, maxOutputLength);
                if (readStatus != NTStatus.STATUS_SUCCESS)
                {
                    return readStatus;
                }

                if (output.Length < messageLength)
                {
                    return NTStatus.STATUS_BUFFER_OVERFLOW;
                }
                else
                {
                    return NTStatus.STATUS_SUCCESS;
                }
            }

            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus QueryDirectory(out List<QueryDirectoryFileInformation> result, object directoryHandle, string fileName, FileInformationClass informationClass)
        {
            result = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus GetFileInformation(out FileInformation result, object handle, FileInformationClass informationClass)
        {
            switch (informationClass)
            {
                case FileInformationClass.FileBasicInformation:
                    {
                        FileBasicInformation information = new FileBasicInformation();
                        information.FileAttributes = FileAttributes.Temporary;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileInformationClass.FileStandardInformation:
                    {
                        FileStandardInformation information = new FileStandardInformation();
                        information.DeletePending = false;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                case FileInformationClass.FileNetworkOpenInformation:
                    {
                        FileNetworkOpenInformation information = new FileNetworkOpenInformation();
                        information.FileAttributes = FileAttributes.Temporary;
                        result = information;
                        return NTStatus.STATUS_SUCCESS;
                    }
                default:
                    result = null;
                    return NTStatus.STATUS_INVALID_INFO_CLASS;
            }
        }

        public NTStatus SetFileInformation(object handle, FileInformation information)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus GetFileSystemInformation(out FileSystemInformation result, FileSystemInformationClass informationClass)
        {
            result = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus SetFileSystemInformation(FileSystemInformation information)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
        {
            result = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            ioRequest = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus Cancel(object ioRequest)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }
    }
}