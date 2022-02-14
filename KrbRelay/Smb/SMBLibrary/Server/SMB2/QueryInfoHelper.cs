/* Copyright (C) 2017-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class QueryInfoHelper
    {
        internal static SMB2Command GetQueryInfoResponse(QueryInfoRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            if (request.InfoType == InfoType.File)
            {
                OpenFileObject openFile = session.GetOpenFileObject(request.FileId);
                if (openFile == null)
                {
                    state.LogToServer(Severity.Verbose, "GetFileInformation failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
                }

                if (share is FileSystemShare)
                {
                    if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
                    {
                        state.LogToServer(Severity.Verbose, "GetFileInformation on '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                    }
                }

                FileInformation fileInformation;
                NTStatus queryStatus = share.FileStore.GetFileInformation(out fileInformation, openFile.Handle, request.FileInformationClass);
                if (queryStatus != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: {3}. (FileId: {4})", share.Name, openFile.Path, request.FileInformationClass, queryStatus, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, queryStatus);
                }

                state.LogToServer(Severity.Information, "GetFileInformation on '{0}{1}' succeeded. Information class: {2}. (FileId: {3})", share.Name, openFile.Path, request.FileInformationClass, request.FileId.Volatile);
                QueryInfoResponse response = new QueryInfoResponse();
                response.SetFileInformation(fileInformation);
                if (response.OutputBuffer.Length > request.OutputBufferLength)
                {
                    response.Header.Status = NTStatus.STATUS_BUFFER_OVERFLOW;
                    response.OutputBuffer = ByteReader.ReadBytes(response.OutputBuffer, 0, (int)request.OutputBufferLength);
                }
                return response;
            }
            else if (request.InfoType == InfoType.FileSystem)
            {
                if (share is FileSystemShare)
                {
                    if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, @"\"))
                    {
                        state.LogToServer(Severity.Verbose, "GetFileSystemInformation on '{0}' failed. User '{1}' was denied access.", share.Name, session.UserName);
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                    }

                    FileSystemInformation fileSystemInformation;
                    NTStatus queryStatus = share.FileStore.GetFileSystemInformation(out fileSystemInformation, request.FileSystemInformationClass);
                    if (queryStatus != NTStatus.STATUS_SUCCESS)
                    {
                        state.LogToServer(Severity.Verbose, "GetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: {2}", share.Name, request.FileSystemInformationClass, queryStatus);
                        return new ErrorResponse(request.CommandName, queryStatus);
                    }

                    state.LogToServer(Severity.Information, "GetFileSystemInformation on '{0}' succeeded. Information class: {1}", share.Name, request.FileSystemInformationClass);
                    QueryInfoResponse response = new QueryInfoResponse();
                    response.SetFileSystemInformation(fileSystemInformation);
                    if (response.OutputBuffer.Length > request.OutputBufferLength)
                    {
                        response.Header.Status = NTStatus.STATUS_BUFFER_OVERFLOW;
                        response.OutputBuffer = ByteReader.ReadBytes(response.OutputBuffer, 0, (int)request.OutputBufferLength);
                    }

                    return response;
                }
            }
            else if (request.InfoType == InfoType.Security)
            {
                OpenFileObject openFile = session.GetOpenFileObject(request.FileId);
                if (openFile == null)
                {
                    state.LogToServer(Severity.Verbose, "GetSecurityInformation failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
                }

                if (share is FileSystemShare)
                {
                    if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, openFile.Path))
                    {
                        state.LogToServer(Severity.Verbose, "GetSecurityInformation on '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                    }
                }

                SecurityDescriptor securityDescriptor;
                NTStatus queryStatus = share.FileStore.GetSecurityInformation(out securityDescriptor, openFile.Handle, request.SecurityInformation);
                if (queryStatus != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "GetSecurityInformation on '{0}{1}' failed. Security information: 0x{2}, NTStatus: {3}. (FileId: {4})", share.Name, openFile.Path, request.SecurityInformation.ToString("X"), queryStatus, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, queryStatus);
                }

                if (securityDescriptor.Length > request.OutputBufferLength)
                {
                    state.LogToServer(Severity.Information, "GetSecurityInformation on '{0}{1}' failed. Security information: 0x{2}, NTStatus: STATUS_BUFFER_TOO_SMALL. (FileId: {3})", share.Name, openFile.Path, request.SecurityInformation.ToString("X"), request.FileId.Volatile);
                    byte[] errorData = LittleEndianConverter.GetBytes((uint)securityDescriptor.Length);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_BUFFER_TOO_SMALL, errorData);
                }

                state.LogToServer(Severity.Information, "GetSecurityInformation on '{0}{1}' succeeded. Security information: 0x{2}. (FileId: {3})", share.Name, openFile.Path, request.SecurityInformation.ToString("X"), request.FileId.Volatile);
                QueryInfoResponse response = new QueryInfoResponse();
                response.SetSecurityInformation(securityDescriptor);
                return response;
            }
            return new ErrorResponse(request.CommandName, NTStatus.STATUS_NOT_SUPPORTED);
        }
    }
}