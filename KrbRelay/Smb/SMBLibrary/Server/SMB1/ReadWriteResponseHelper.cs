/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class ReadWriteResponseHelper
    {
        internal static SMB1Command GetReadResponse(SMB1Header header, ReadRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Read failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return new ErrorResponse(request.CommandName);
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "Read from '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return new ErrorResponse(request.CommandName);
                }
            }

            byte[] data;
            header.Status = share.FileStore.ReadFile(out data, openFile.Handle, request.ReadOffsetInBytes, request.CountOfBytesToRead);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Read from '{0}{1}' failed. NTStatus: {2}. (FID: {3})", share.Name, openFile.Path, header.Status, request.FID);
                return new ErrorResponse(request.CommandName);
            }

            ReadResponse response = new ReadResponse();
            response.Bytes = data;
            response.CountOfBytesReturned = (ushort)data.Length;
            return response;
        }

        internal static SMB1Command GetReadResponse(SMB1Header header, ReadAndXRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Read failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return new ErrorResponse(request.CommandName);
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "Read from '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return new ErrorResponse(request.CommandName);
                }
            }

            uint maxCount = request.MaxCount;
            if ((share is FileSystemShare) && state.LargeRead)
            {
                maxCount = request.MaxCountLarge;
            }
            byte[] data;
            header.Status = share.FileStore.ReadFile(out data, openFile.Handle, (long)request.Offset, (int)maxCount);
            if (header.Status == NTStatus.STATUS_END_OF_FILE)
            {
                // [MS-CIFS] Windows servers set the DataLength field to 0x0000 and return STATUS_SUCCESS.
                // JCIFS expects the same response.
                data = new byte[0];
                header.Status = NTStatus.STATUS_SUCCESS;
            }
            else if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Read from '{0}{1}' failed. NTStatus: {2}. (FID: {3})", share.Name, openFile.Path, header.Status, request.FID);
                return new ErrorResponse(request.CommandName);
            }

            ReadAndXResponse response = new ReadAndXResponse();
            if (share is FileSystemShare)
            {
                // If the client reads from a disk file, this field MUST be set to -1 (0xFFFF)
                response.Available = 0xFFFF;
            }
            response.Data = data;
            return response;
        }

        internal static SMB1Command GetWriteResponse(SMB1Header header, WriteRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Write failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return new ErrorResponse(request.CommandName);
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "Write to '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return new ErrorResponse(request.CommandName);
                }
            }

            int numberOfBytesWritten;
            header.Status = share.FileStore.WriteFile(out numberOfBytesWritten, openFile.Handle, request.WriteOffsetInBytes, request.Data);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Write to '{0}{1}' failed. NTStatus: {2}. (FID: {3})", share.Name, openFile.Path, header.Status, request.FID);
                return new ErrorResponse(request.CommandName);
            }
            WriteResponse response = new WriteResponse();
            response.CountOfBytesWritten = (ushort)numberOfBytesWritten;
            return response;
        }

        internal static SMB1Command GetWriteResponse(SMB1Header header, WriteAndXRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Write failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return new ErrorResponse(request.CommandName);
            }

            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, openFile.Path))
                {
                    state.LogToServer(Severity.Verbose, "Write to '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return new ErrorResponse(request.CommandName);
                }
            }

            int numberOfBytesWritten;
            header.Status = share.FileStore.WriteFile(out numberOfBytesWritten, openFile.Handle, (long)request.Offset, request.Data);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Write to '{0}{1}' failed. NTStatus: {2}. (FID: {3})", share.Name, openFile.Path, header.Status, request.FID);
                return new ErrorResponse(request.CommandName);
            }
            WriteAndXResponse response = new WriteAndXResponse();
            response.Count = (uint)numberOfBytesWritten;
            if (share is FileSystemShare)
            {
                // If the client wrote to a disk file, this field MUST be set to 0xFFFF.
                response.Available = 0xFFFF;
            }
            return response;
        }

        internal static SMB1Command GetFlushResponse(SMB1Header header, FlushRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            if (request.FID == 0xFFFF)
            {
                // [MS-CIFS] If the FID is 0xFFFF, the Server.Connection.FileOpenTable MUST be scanned for
                // all files that were opened by the PID listed in the request header.
                // The server MUST attempt to flush each Server.Open so listed.
                return new FlushResponse();
            }

            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Flush failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return new ErrorResponse(request.CommandName);
            }
            header.Status = share.FileStore.FlushFileBuffers(openFile.Handle);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Flush '{0}{1}' failed. NTStatus: {2}. (FID: {3})", share.Name, openFile.Path, header.Status, request.FID);
                return new ErrorResponse(request.CommandName);
            }
            return new FlushResponse();
        }
    }
}