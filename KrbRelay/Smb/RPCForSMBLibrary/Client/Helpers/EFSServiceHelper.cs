/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;
using System;

namespace SMBLibrary.Client
{
    public class EFSServiceHelper
    {
        public static UInt32 EfsRpcOpenFileRaw(RPCCallHelper rpc, out EXImportContextHandle hContext, string FileName, Int32 Flags, out NTStatus status)
        {
            EfsRpcOpenFileRawRequest openFileRequest = new EfsRpcOpenFileRawRequest();
            openFileRequest.FileName = FileName;
            openFileRequest.Flags = Flags;

            EfsRpcOpenFileRawResponse openFileResponse;

            status = rpc.ExecuteCall((ushort)EFSServiceOpName.EfsRpcOpenFileRaw, openFileRequest, out openFileResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                hContext = new EXImportContextHandle();
                return 0;
            }
            hContext = openFileResponse.ContextHandle;
            return openFileResponse.Return;
        }

        public static void EfsRpcCloseRaw(RPCCallHelper rpc, ref EXImportContextHandle handle, out NTStatus status)
        {
            EfsRpcCloseRawRequest closeRequest = new EfsRpcCloseRawRequest();
            closeRequest.handle = handle;

            EfsRpcCloseRawResponse closeResponse;

            status = rpc.ExecuteCall((ushort)LsaRemoteServiceOpName.LsarClose, closeRequest, out closeResponse);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return;
            }
            handle = closeResponse.Handle;
        }
    }
}