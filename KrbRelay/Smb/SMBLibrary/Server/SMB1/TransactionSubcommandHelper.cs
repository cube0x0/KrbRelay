/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using System;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class TransactionSubcommandHelper
    {
        internal static TransactionTransactNamedPipeResponse GetSubcommandResponse(SMB1Header header, uint maxDataCount, TransactionTransactNamedPipeRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(subcommand.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "TransactNamedPipe failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, subcommand.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            int maxOutputLength = (int)maxDataCount;
            byte[] output;
            header.Status = share.FileStore.DeviceIOControl(openFile.Handle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, subcommand.WriteData, out output, maxOutputLength);
            if (header.Status != NTStatus.STATUS_SUCCESS && header.Status != NTStatus.STATUS_BUFFER_OVERFLOW)
            {
                state.LogToServer(Severity.Verbose, "TransactNamedPipe failed. NTStatus: {0}.", header.Status);
                return null;
            }
            TransactionTransactNamedPipeResponse response = new TransactionTransactNamedPipeResponse();
            response.ReadData = output;
            return response;
        }

        internal static void ProcessSubcommand(SMB1Header header, uint timeout, string name, TransactionWaitNamedPipeRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            if (!name.StartsWith(@"\PIPE\", StringComparison.OrdinalIgnoreCase))
            {
                // [MS-CIFS] The name field MUST be set to the name of the pipe being waited for, in the format \PIPE\<pipename>
                state.LogToServer(Severity.Verbose, "TransactWaitNamedPipe failed. Invalid pipe name: {0}.", name);
                header.Status = NTStatus.STATUS_INVALID_SMB;
            }

            string pipeName = name.Substring(6);
            PipeWaitRequest pipeWaitRequest = new PipeWaitRequest();
            pipeWaitRequest.Timeout = timeout;
            pipeWaitRequest.TimeSpecified = true;
            pipeWaitRequest.Name = pipeName;
            byte[] input = pipeWaitRequest.GetBytes();
            byte[] output;
            header.Status = share.FileStore.DeviceIOControl(null, (uint)IoControlCode.FSCTL_PIPE_WAIT, input, out output, 0);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "TransactWaitNamedPipe failed. Pipe name: {0}. NTStatus: {1}.", pipeName, header.Status);
            }
            else
            {
                state.LogToServer(Severity.Verbose, "TransactWaitNamedPipe succeeded. Pipe name: {0}.", pipeName);
            }
        }
    }
}