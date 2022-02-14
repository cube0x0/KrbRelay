/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using SMBLibrary.Services;
using System;

namespace SMBLibrary.Client
{
    public class NamedPipeHelper
    {
        public static NTStatus BindPipe(INTFileStore namedPipeShare, string pipeName, Guid interfaceGuid, uint interfaceVersion, out object pipeHandle, out int maxTransmitFragmentSize)
        {
            maxTransmitFragmentSize = 0;
            FileStatus fileStatus;
            NTStatus status = namedPipeShare.CreateFile(out pipeHandle, out fileStatus, pipeName, (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA), 0, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, 0, null);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            BindPDU bindPDU = new BindPDU();
            bindPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            bindPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            bindPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            bindPDU.MaxTransmitFragmentSize = 5680;
            bindPDU.MaxReceiveFragmentSize = 5680;

            ContextElement serviceContext = new ContextElement();
            serviceContext.AbstractSyntax = new SyntaxID(interfaceGuid, interfaceVersion);
            serviceContext.TransferSyntaxList.Add(new SyntaxID(RemoteServiceHelper.NDRTransferSyntaxIdentifier, RemoteServiceHelper.NDRTransferSyntaxVersion));

            bindPDU.ContextList.Add(serviceContext);

            byte[] input = bindPDU.GetBytes();
            byte[] output;
            status = namedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out output, 4096);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            BindAckPDU bindAckPDU = RPCPDU.GetPDU(output, 0) as BindAckPDU;
            if (bindAckPDU == null)
            {
                return NTStatus.STATUS_NOT_SUPPORTED;
            }

            maxTransmitFragmentSize = bindAckPDU.MaxTransmitFragmentSize;
            return NTStatus.STATUS_SUCCESS;
        }
    }
}