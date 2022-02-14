/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using System.IO;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class NTCreateHelper
    {
        internal static SMB1Command GetNTCreateResponse(SMB1Header header, NTCreateAndXRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            bool isExtended = (request.Flags & NTCreateFlags.NT_CREATE_REQUEST_EXTENDED_RESPONSE) > 0;
            string path = request.FileName;
            if (!path.StartsWith(@"\"))
            {
                path = @"\" + path;
            }

            FileAccess createAccess = NTFileStoreHelper.ToCreateFileAccess(request.DesiredAccess, request.CreateDisposition);
            if (share is FileSystemShare)
            {
                if (!((FileSystemShare)share).HasAccess(session.SecurityContext, path, createAccess))
                {
                    state.LogToServer(Severity.Verbose, "Create: Opening '{0}{1}' failed. User '{2}' was denied access.", share.Name, request.FileName, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return new ErrorResponse(request.CommandName);
                }
            }

            object handle;
            FileStatus fileStatus;
            FileAttributes fileAttributes = ToFileAttributes(request.ExtFileAttributes);
            // GetFileInformation/FileNetworkOpenInformation requires FILE_READ_ATTRIBUTES
            AccessMask desiredAccess = request.DesiredAccess | (AccessMask)FileAccessMask.FILE_READ_ATTRIBUTES;
            NTStatus createStatus = share.FileStore.CreateFile(out handle, out fileStatus, path, desiredAccess, fileAttributes, request.ShareAccess, request.CreateDisposition, request.CreateOptions, session.SecurityContext);
            if (createStatus != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "Create: Opening '{0}{1}' failed. NTStatus: {2}.", share.Name, path, createStatus);
                header.Status = createStatus;
                return new ErrorResponse(request.CommandName);
            }

            FileAccess fileAccess = NTFileStoreHelper.ToFileAccess(desiredAccess);
            ushort? fileID = session.AddOpenFile(header.TID, share.Name, path, handle, fileAccess);
            if (!fileID.HasValue)
            {
                share.FileStore.CloseFile(handle);
                state.LogToServer(Severity.Verbose, "Create: Opening '{0}{1}' failed. Too many open files.", share.Name, path);
                header.Status = NTStatus.STATUS_TOO_MANY_OPENED_FILES;
                return new ErrorResponse(request.CommandName);
            }

            string fileAccessString = fileAccess.ToString().Replace(", ", "|");
            string shareAccessString = request.ShareAccess.ToString().Replace(", ", "|");
            state.LogToServer(Severity.Verbose, "Create: Opened '{0}{1}', FileAccess: {2}, ShareAccess: {3}. (UID: {4}, TID: {5}, FID: {6})", share.Name, path, fileAccessString, shareAccessString, header.UID, header.TID, fileID.Value);
            if (share is NamedPipeShare)
            {
                if (isExtended)
                {
                    return CreateResponseExtendedForNamedPipe(fileID.Value, FileStatus.FILE_OPENED);
                }
                else
                {
                    return CreateResponseForNamedPipe(fileID.Value, FileStatus.FILE_OPENED);
                }
            }
            else // FileSystemShare
            {
                FileNetworkOpenInformation fileInfo = NTFileStoreHelper.GetNetworkOpenInformation(share.FileStore, handle);
                if (isExtended)
                {
                    NTCreateAndXResponseExtended response = CreateResponseExtendedFromFileInformation(fileInfo, fileID.Value, fileStatus);
                    return response;
                }
                else
                {
                    NTCreateAndXResponse response = CreateResponseFromFileInformation(fileInfo, fileID.Value, fileStatus);
                    return response;
                }
            }
        }

        private static NTCreateAndXResponse CreateResponseForNamedPipe(ushort fileID, FileStatus fileStatus)
        {
            NTCreateAndXResponse response = new NTCreateAndXResponse();
            response.FID = fileID;
            response.CreateDisposition = ToCreateDisposition(fileStatus);
            response.ExtFileAttributes = ExtendedFileAttributes.Normal;
            response.ResourceType = ResourceType.FileTypeMessageModePipe;
            response.NMPipeStatus.ICount = 255;
            response.NMPipeStatus.ReadMode = ReadMode.MessageMode;
            response.NMPipeStatus.NamedPipeType = NamedPipeType.MessageModePipe;
            return response;
        }

        private static NTCreateAndXResponseExtended CreateResponseExtendedForNamedPipe(ushort fileID, FileStatus fileStatus)
        {
            NTCreateAndXResponseExtended response = new NTCreateAndXResponseExtended();
            response.FID = fileID;
            response.CreateDisposition = ToCreateDisposition(fileStatus);
            response.ExtFileAttributes = ExtendedFileAttributes.Normal;
            response.ResourceType = ResourceType.FileTypeMessageModePipe;
            NamedPipeStatus status = new NamedPipeStatus();
            status.ICount = 255;
            status.ReadMode = ReadMode.MessageMode;
            status.NamedPipeType = NamedPipeType.MessageModePipe;
            response.NMPipeStatus = status;
            response.MaximalAccessRights = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA | FileAccessMask.FILE_APPEND_DATA |
                                                        FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                        FileAccessMask.FILE_EXECUTE |
                                                        FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                        AccessMask.DELETE | AccessMask.READ_CONTROL | AccessMask.WRITE_DAC | AccessMask.WRITE_OWNER | AccessMask.SYNCHRONIZE;
            response.GuestMaximalAccessRights = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA |
                                                             FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                             FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                             AccessMask.READ_CONTROL | AccessMask.SYNCHRONIZE;
            return response;
        }

        private static NTCreateAndXResponse CreateResponseFromFileInformation(FileNetworkOpenInformation fileInfo, ushort fileID, FileStatus fileStatus)
        {
            NTCreateAndXResponse response = new NTCreateAndXResponse();
            response.FID = fileID;
            response.CreateDisposition = ToCreateDisposition(fileStatus);
            response.CreateTime = fileInfo.CreationTime;
            response.LastAccessTime = fileInfo.LastAccessTime;
            response.LastWriteTime = fileInfo.LastWriteTime;
            response.LastChangeTime = fileInfo.LastWriteTime;
            response.AllocationSize = fileInfo.AllocationSize;
            response.EndOfFile = fileInfo.EndOfFile;
            response.ExtFileAttributes = (ExtendedFileAttributes)fileInfo.FileAttributes;
            response.ResourceType = ResourceType.FileTypeDisk;
            response.Directory = fileInfo.IsDirectory;
            return response;
        }

        private static NTCreateAndXResponseExtended CreateResponseExtendedFromFileInformation(FileNetworkOpenInformation fileInfo, ushort fileID, FileStatus fileStatus)
        {
            NTCreateAndXResponseExtended response = new NTCreateAndXResponseExtended();
            response.FID = fileID;
            response.CreateDisposition = ToCreateDisposition(fileStatus);
            response.CreateTime = fileInfo.CreationTime;
            response.LastAccessTime = fileInfo.LastAccessTime;
            response.LastWriteTime = fileInfo.LastWriteTime;
            response.LastChangeTime = fileInfo.LastWriteTime;
            response.ExtFileAttributes = (ExtendedFileAttributes)fileInfo.FileAttributes;
            response.AllocationSize = fileInfo.AllocationSize;
            response.EndOfFile = fileInfo.EndOfFile;
            response.ResourceType = ResourceType.FileTypeDisk;
            response.FileStatusFlags = FileStatusFlags.NO_EAS | FileStatusFlags.NO_SUBSTREAMS | FileStatusFlags.NO_REPARSETAG;
            response.Directory = fileInfo.IsDirectory;
            response.MaximalAccessRights = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA | FileAccessMask.FILE_APPEND_DATA |
                                                        FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                        FileAccessMask.FILE_EXECUTE |
                                                        FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                        AccessMask.DELETE | AccessMask.READ_CONTROL | AccessMask.WRITE_DAC | AccessMask.WRITE_OWNER | AccessMask.SYNCHRONIZE;
            response.GuestMaximalAccessRights = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA |
                                                             FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                             FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                             AccessMask.READ_CONTROL | AccessMask.SYNCHRONIZE;
            return response;
        }

        private static CreateDisposition ToCreateDisposition(FileStatus fileStatus)
        {
            if (fileStatus == FileStatus.FILE_SUPERSEDED)
            {
                return CreateDisposition.FILE_SUPERSEDE;
            }
            else if (fileStatus == FileStatus.FILE_CREATED)
            {
                return CreateDisposition.FILE_CREATE;
            }
            else if (fileStatus == FileStatus.FILE_OVERWRITTEN)
            {
                return CreateDisposition.FILE_OVERWRITE;
            }
            else
            {
                return CreateDisposition.FILE_OPEN;
            }
        }

        private static FileAttributes ToFileAttributes(ExtendedFileAttributes extendedFileAttributes)
        {
            // We only return flags that can be used with NtCreateFile
            FileAttributes fileAttributes = FileAttributes.ReadOnly |
                                              FileAttributes.Hidden |
                                              FileAttributes.System |
                                              FileAttributes.Archive |
                                              FileAttributes.Normal |
                                              FileAttributes.Temporary |
                                              FileAttributes.Offline |
                                              FileAttributes.Encrypted;
            return (fileAttributes & (FileAttributes)extendedFileAttributes);
        }
    }
}