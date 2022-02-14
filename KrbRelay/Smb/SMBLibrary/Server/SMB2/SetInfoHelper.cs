/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;
using System;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class SetInfoHelper
    {
        internal static SMB2Command GetSetInfoResponse(SetInfoRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            OpenFileObject openFile = null;
            if (request.InfoType == InfoType.File || request.InfoType == InfoType.Security)
            {
                openFile = session.GetOpenFileObject(request.FileId);
                if (openFile == null)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
                }

                if (share is FileSystemShare)
                {
                    if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, openFile.Path))
                    {
                        state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. User '{2}' was denied access.", share.Name, openFile.Path, session.UserName);
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                    }
                }
            }
            else if (request.InfoType == InfoType.FileSystem)
            {
                if (share is FileSystemShare)
                {
                    if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, @"\"))
                    {
                        state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. User '{1}' was denied access.", share.Name, session.UserName);
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                    }
                }
            }

            if (request.InfoType == InfoType.File)
            {
                FileInformation information;
                try
                {
                    information = FileInformation.GetFileInformation(request.Buffer, 0, request.FileInformationClass);
                }
                catch (UnsupportedInformationLevelException)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: STATUS_INVALID_INFO_CLASS.", share.Name, openFile.Path, request.FileInformationClass);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_INFO_CLASS);
                }
                catch (NotImplementedException)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: STATUS_NOT_SUPPORTED.", share.Name, openFile.Path, request.FileInformationClass);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_NOT_SUPPORTED);
                }
                catch (Exception)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: STATUS_INVALID_PARAMETER.", share.Name, openFile.Path, request.FileInformationClass);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                }

                if ((share is FileSystemShare) && (information is FileRenameInformationType2))
                {
                    string newFileName = ((FileRenameInformationType2)information).FileName;
                    if (!newFileName.StartsWith(@"\"))
                    {
                        newFileName = @"\" + newFileName;
                    }
                    if (!((FileSystemShare)share).HasWriteAccess(session.SecurityContext, newFileName))
                    {
                        state.LogToServer(Severity.Verbose, "SetFileInformation: Rename '{0}{1}' to '{0}{2}' failed. User '{3}' was denied access.", share.Name, openFile.Path, newFileName, session.UserName);
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                    }
                }

                NTStatus status = share.FileStore.SetFileInformation(openFile.Handle, information);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "SetFileInformation on '{0}{1}' failed. Information class: {2}, NTStatus: {3}. (FileId: {4})", share.Name, openFile.Path, request.FileInformationClass, status, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, status);
                }

                if (information is FileRenameInformationType2)
                {
                    string newFileName = ((FileRenameInformationType2)information).FileName;
                    if (!newFileName.StartsWith(@"\"))
                    {
                        newFileName = @"\" + newFileName;
                    }
                    state.LogToServer(Severity.Verbose, "SetFileInformation: Rename '{0}{1}' to '{0}{2}' succeeded. (FileId: {3})", share.Name, openFile.Path, newFileName, request.FileId.Volatile);
                    openFile.Path = newFileName;
                }
                else
                {
                    state.LogToServer(Severity.Information, "SetFileInformation on '{0}{1}' succeeded. Information class: {2}. (FileId: {3})", share.Name, openFile.Path, request.FileInformationClass, request.FileId.Volatile);
                }
                return new SetInfoResponse();
            }
            else if (request.InfoType == InfoType.FileSystem)
            {
                FileSystemInformation fileSystemInformation;
                try
                {
                    fileSystemInformation = FileSystemInformation.GetFileSystemInformation(request.Buffer, 0, request.FileSystemInformationClass);
                }
                catch (UnsupportedInformationLevelException)
                {
                    state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: STATUS_INVALID_INFO_CLASS.", share.Name, request.FileSystemInformationClass);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_INFO_CLASS);
                }
                catch (Exception)
                {
                    state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: STATUS_INVALID_PARAMETER.", share.Name, request.FileSystemInformationClass);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                }

                NTStatus status = share.FileStore.SetFileSystemInformation(fileSystemInformation);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' failed. Information class: {1}, NTStatus: {2}.", share.Name, request.FileSystemInformationClass, status);
                    return new ErrorResponse(request.CommandName, status);
                }

                state.LogToServer(Severity.Verbose, "SetFileSystemInformation on '{0}' succeeded. Information class: {1}.", share.Name, request.FileSystemInformationClass);
                return new SetInfoResponse();
            }
            else if (request.InfoType == InfoType.Security)
            {
                SecurityDescriptor securityDescriptor;
                try
                {
                    securityDescriptor = new SecurityDescriptor(request.Buffer, 0);
                }
                catch
                {
                    state.LogToServer(Severity.Verbose, "SetSecurityInformation on '{0}{1}' failed. NTStatus: STATUS_INVALID_PARAMETER.", share.Name, openFile.Path);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                }

                NTStatus status = share.FileStore.SetSecurityInformation(openFile, request.SecurityInformation, securityDescriptor);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "SetSecurityInformation on '{0}{1}' failed. Security information: 0x{2}, NTStatus: {3}. (FileId: {4})", share.Name, openFile.Path, request.SecurityInformation.ToString("X"), status, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, status);
                }

                state.LogToServer(Severity.Information, "SetSecurityInformation on '{0}{1}' succeeded. Security information: 0x{2}. (FileId: {3})", share.Name, openFile.Path, request.SecurityInformation.ToString("X"), request.FileId.Volatile);
                return new SetInfoResponse();
            }
            return new ErrorResponse(request.CommandName, NTStatus.STATUS_NOT_SUPPORTED);
        }
    }
}