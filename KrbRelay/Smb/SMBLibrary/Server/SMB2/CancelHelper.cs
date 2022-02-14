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
    internal class CancelHelper
    {
        internal static SMB2Command GetCancelResponse(CancelRequest request, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            if (request.Header.IsAsync)
            {
                SMB2AsyncContext context = state.GetAsyncContext(request.Header.AsyncID);
                if (context != null)
                {
                    ISMBShare share = session.GetConnectedTree(context.TreeID);
                    OpenFileObject openFile = session.GetOpenFileObject(context.FileID);
                    NTStatus status = share.FileStore.Cancel(context.IORequest);
                    if (openFile != null)
                    {
                        state.LogToServer(Severity.Information, "Cancel: Requested cancel on '{0}{1}'. NTStatus: {2}, AsyncID: {3}.", share.Name, openFile.Path, status, context.AsyncID);
                    }
                    if (status == NTStatus.STATUS_SUCCESS ||
                        status == NTStatus.STATUS_CANCELLED ||
                        status == NTStatus.STATUS_NOT_SUPPORTED) // See ChangeNotifyHelper.cs
                    {
                        state.RemoveAsyncContext(context);
                        // [MS-SMB2] If the target request is successfully canceled, the target request MUST be failed by sending
                        // an ERROR response packet [..] with the status field of the SMB2 header set to STATUS_CANCELLED.
                        ErrorResponse response = new ErrorResponse(request.CommandName, NTStatus.STATUS_CANCELLED);
                        response.Header.IsAsync = true;
                        response.Header.AsyncID = context.AsyncID;
                        return response;
                    }
                    // [MS-SMB2] If the target request is not successfully canceled [..] no response is sent.
                    // Note: Failing to respond might cause the client to disconnect the connection as per [MS-SMB2] 3.2.6.1 Request Expiration Timer Event
                    return null;
                }
                else
                {
                    // [MS-SMB2] If a request is not found [..] no response is sent.
                    return null;
                }
            }
            else
            {
                // [MS-SMB2] the SMB2 CANCEL Request MUST use an ASYNC header for canceling requests that have received an interim response.
                // [MS-SMB2] If the target request is not successfully canceled [..] no response is sent.
                return null;
            }
        }
    }
}