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
    internal class IOCtlHelper
    {
        internal static SMB2Command GetIOCtlResponse(IOCtlRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            string ctlCode = Enum.IsDefined(typeof(IoControlCode), request.CtlCode) ? ((IoControlCode)request.CtlCode).ToString() : ("0x" + request.CtlCode.ToString("X8"));
            if (!request.IsFSCtl)
            {
                // [MS-SMB2] If the Flags field of the request is not SMB2_0_IOCTL_IS_FSCTL the server MUST fail the request with STATUS_NOT_SUPPORTED.
                state.LogToServer(Severity.Verbose, "IOCTL: Non-FSCTL requests are not supported. CTL Code: {0}", ctlCode);
                return new ErrorResponse(request.CommandName, NTStatus.STATUS_NOT_SUPPORTED);
            }

            if (request.CtlCode == (uint)IoControlCode.FSCTL_DFS_GET_REFERRALS ||
                request.CtlCode == (uint)IoControlCode.FSCTL_DFS_GET_REFERRALS_EX)
            {
                // [MS-SMB2] 3.3.5.15.2 Handling a DFS Referral Information Request
                state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. NTStatus: STATUS_FS_DRIVER_REQUIRED.", ctlCode);
                return new ErrorResponse(request.CommandName, NTStatus.STATUS_FS_DRIVER_REQUIRED);
            }

            object handle;
            if (request.CtlCode == (uint)IoControlCode.FSCTL_PIPE_WAIT ||
                request.CtlCode == (uint)IoControlCode.FSCTL_VALIDATE_NEGOTIATE_INFO ||
                request.CtlCode == (uint)IoControlCode.FSCTL_QUERY_NETWORK_INTERFACE_INFO)
            {
                // [MS-SMB2] 3.3.5.15 - FSCTL_PIPE_WAIT / FSCTL_QUERY_NETWORK_INTERFACE_INFO /
                // FSCTL_VALIDATE_NEGOTIATE_INFO requests MUST have FileId set to 0xFFFFFFFFFFFFFFFF.
                if (request.FileId.Persistent != 0xFFFFFFFFFFFFFFFF || request.FileId.Volatile != 0xFFFFFFFFFFFFFFFF)
                {
                    state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. FileId MUST be 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", ctlCode);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                }
                handle = null;
            }
            else
            {
                OpenFileObject openFile = session.GetOpenFileObject(request.FileId);
                if (openFile == null)
                {
                    state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. Invalid FileId. (SessionID: {1}, TreeID: {2}, FileId: {3})", ctlCode, request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
                }
                handle = openFile.Handle;
            }

            int maxOutputLength = (int)request.MaxOutputResponse;
            byte[] output;
            NTStatus status = share.FileStore.DeviceIOControl(handle, request.CtlCode, request.Input, out output, maxOutputLength);
            if (status != NTStatus.STATUS_SUCCESS && status != NTStatus.STATUS_BUFFER_OVERFLOW)
            {
                state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. NTStatus: {1}.", ctlCode, status);
                return new ErrorResponse(request.CommandName, status);
            }

            state.LogToServer(Severity.Verbose, "IOCTL succeeded. CTL Code: {0}.", ctlCode);
            IOCtlResponse response = new IOCtlResponse();
            response.Header.Status = status;
            response.CtlCode = request.CtlCode;
            response.FileId = request.FileId;
            response.Output = output;
            return response;
        }
    }
}