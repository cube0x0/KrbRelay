/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class CloseHelper
    {
        internal static SMB2Command GetCloseResponse(CloseRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FileId);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Close failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                return new ErrorResponse(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
            }

            NTStatus closeStatus = share.FileStore.CloseFile(openFile.Handle);
            if (closeStatus != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Information, "Close: Closing '{0}{1}' failed. NTStatus: {2}. (SessionID: {3}, TreeID: {4}, FileId: {5})", share.Name, openFile.Path, closeStatus, request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                return new ErrorResponse(request.CommandName, closeStatus);
            }

            state.LogToServer(Severity.Information, "Close: Closed '{0}{1}'. (SessionID: {2}, TreeID: {3}, FileId: {4})", share.Name, openFile.Path, request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
            session.RemoveOpenFile(request.FileId);
            CloseResponse response = new CloseResponse();
            if (request.PostQueryAttributes)
            {
                FileNetworkOpenInformation fileInfo = NTFileStoreHelper.GetNetworkOpenInformation(share.FileStore, openFile.Path, session.SecurityContext);
                if (fileInfo != null)
                {
                    response.CreationTime = fileInfo.CreationTime;
                    response.LastAccessTime = fileInfo.LastAccessTime;
                    response.LastWriteTime = fileInfo.LastWriteTime;
                    response.ChangeTime = fileInfo.ChangeTime;
                    response.AllocationSize = fileInfo.AllocationSize;
                    response.EndofFile = fileInfo.EndOfFile;
                    response.FileAttributes = fileInfo.FileAttributes;
                }
            }
            return response;
        }
    }
}