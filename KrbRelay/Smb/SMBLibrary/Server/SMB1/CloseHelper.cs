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
    internal class CloseHelper
    {
        internal static SMB1Command GetCloseResponse(SMB1Header header, CloseRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Close failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_SMB_BAD_FID;
                return new ErrorResponse(request.CommandName);
            }

            header.Status = share.FileStore.CloseFile(openFile.Handle);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Information, "Close: Closing '{0}{1}' failed. NTStatus: {2}. (UID: {3}, TID: {4}, FID: {5})", share.Name, openFile.Path, header.Status, header.UID, header.TID, request.FID);
                return new ErrorResponse(request.CommandName);
            }

            state.LogToServer(Severity.Information, "Close: Closed '{0}{1}'. (UID: {2}, TID: {3}, FID: {4})", share.Name, openFile.Path, header.UID, header.TID, request.FID);
            session.RemoveOpenFile(request.FID);
            return new CloseResponse();
        }

        internal static SMB1Command GetFindClose2Response(SMB1Header header, FindClose2Request request, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            session.RemoveOpenSearch(request.SearchHandle);
            return new FindClose2Response();
        }
    }
}