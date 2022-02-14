/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class CancelHelper
    {
        internal static void ProcessNTCancelRequest(SMB1Header header, NTCancelRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            SMB1AsyncContext context = state.GetAsyncContext(header.UID, header.TID, header.PID, header.MID);
            if (context != null)
            {
                NTStatus status = share.FileStore.Cancel(context.IORequest);
                OpenFileObject openFile = session.GetOpenFileObject(context.FileID);
                if (openFile != null)
                {
                    state.LogToServer(Severity.Information, "Cancel: Requested cancel on '{0}{1}', NTStatus: {2}. PID: {3}. MID: {4}.", share.Name, openFile.Path, status, context.PID, context.MID);
                }
                if (status == NTStatus.STATUS_SUCCESS || status == NTStatus.STATUS_CANCELLED)
                {
                    state.RemoveAsyncContext(context);
                }
            }
        }
    }
}