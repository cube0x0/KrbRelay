/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.Services
{
    public class RemoteServiceHelper
    {
        // v1 - DCE 1.1: Remote Procedure Call
        // v2 - [MS-RPCE] 2.2.4.12 NDR Transfer Syntax Identifier
        public static readonly Guid NDRTransferSyntaxIdentifier = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860");

        public const int NDRTransferSyntaxVersion = 2;

        // v1 - [MS-RPCE] 3.3.1.5.3 - Bind Time Feature Negotiation
        // Windows will reject this:
        //private static readonly Guid BindTimeFeatureIdentifier1 = new Guid("6CB71C2C-9812-4540-0100-000000000000");
        // Windows will return NegotiationResult.NegotiateAck:
        public static readonly Guid BindTimeFeatureIdentifier3 = new Guid("6CB71C2C-9812-4540-0300-000000000000");

        public const int BindTimeFeatureIdentifierVersion = 1;

        private static uint m_associationGroupID = 1;

        public static BindAckPDU GetRPCBindResponse(BindPDU bindPDU, RemoteService service)
        {
            BindAckPDU bindAckPDU = new BindAckPDU();
            bindAckPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            bindAckPDU.DataRepresentation = bindPDU.DataRepresentation;
            bindAckPDU.CallID = bindPDU.CallID;
            // See DCE 1.1: Remote Procedure Call - 12.6.3.6
            // The client should set the assoc_group_id field either to 0 (zero), to indicate a new association group,
            // or to the known value. When the server receives a value of 0, this indicates that the client
            // has requested a new association group, and it assigns a server unique value to the group.
            if (bindPDU.AssociationGroupID == 0)
            {
                bindAckPDU.AssociationGroupID = m_associationGroupID;
                m_associationGroupID++;
                if (m_associationGroupID == 0)
                {
                    m_associationGroupID++;
                }
            }
            else
            {
                bindAckPDU.AssociationGroupID = bindPDU.AssociationGroupID;
            }
            bindAckPDU.SecondaryAddress = @"\PIPE\" + service.PipeName;
            bindAckPDU.MaxTransmitFragmentSize = bindPDU.MaxReceiveFragmentSize;
            bindAckPDU.MaxReceiveFragmentSize = bindPDU.MaxTransmitFragmentSize;
            foreach (ContextElement element in bindPDU.ContextList)
            {
                ResultElement resultElement = new ResultElement();
                if (element.AbstractSyntax.InterfaceUUID.Equals(service.InterfaceGuid))
                {
                    int index = IndexOfSupportedTransferSyntax(element.TransferSyntaxList);
                    if (index >= 0)
                    {
                        resultElement.Result = NegotiationResult.Acceptance;
                        resultElement.TransferSyntax = element.TransferSyntaxList[index];
                    }
                    else if (element.TransferSyntaxList.Contains(new SyntaxID(BindTimeFeatureIdentifier3, 1)))
                    {
                        // [MS-RPCE] 3.3.1.5.3
                        // If the server supports bind time feature negotiation, it MUST reply with the result
                        // field in the p_result_t structure of the bind_ack PDU equal to negotiate_ack.
                        resultElement.Result = NegotiationResult.NegotiateAck;
                        resultElement.Reason = RejectionReason.AbstractSyntaxNotSupported;
                    }
                    else
                    {
                        resultElement.Result = NegotiationResult.ProviderRejection;
                        resultElement.Reason = RejectionReason.ProposedTransferSyntaxesNotSupported;
                    }
                }
                else
                {
                    resultElement.Result = NegotiationResult.ProviderRejection;
                    resultElement.Reason = RejectionReason.AbstractSyntaxNotSupported;
                }
                bindAckPDU.ResultList.Add(resultElement);
            }

            return bindAckPDU;
        }

        private static int IndexOfSupportedTransferSyntax(List<SyntaxID> syntaxList)
        {
            List<SyntaxID> supportedTransferSyntaxes = new List<SyntaxID>();
            supportedTransferSyntaxes.Add(new SyntaxID(NDRTransferSyntaxIdentifier, 1));
            // [MS-RPCE] Version 2.0 data representation protocol:
            supportedTransferSyntaxes.Add(new SyntaxID(NDRTransferSyntaxIdentifier, 2));

            for (int index = 0; index < syntaxList.Count; index++)
            {
                if (supportedTransferSyntaxes.Contains(syntaxList[index]))
                {
                    return index;
                }
            }
            return -1;
        }

        public static List<RPCPDU> GetRPCResponse(RequestPDU requestPDU, RemoteService service, int maxTransmitFragmentSize)
        {
            List<RPCPDU> result = new List<RPCPDU>();
            byte[] responseBytes;
            try
            {
                responseBytes = service.GetResponseBytes(requestPDU.OpNum, requestPDU.Data);
            }
            catch (UnsupportedOpNumException)
            {
                FaultPDU faultPDU = new FaultPDU();
                faultPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment | PacketFlags.DidNotExecute;
                faultPDU.DataRepresentation = requestPDU.DataRepresentation;
                faultPDU.CallID = requestPDU.CallID;
                faultPDU.AllocationHint = RPCPDU.CommonFieldsLength + FaultPDU.FaultFieldsLength;
                // Windows will return either nca_s_fault_ndr or nca_op_rng_error.
                faultPDU.Status = FaultStatus.OpRangeError;
                result.Add(faultPDU);
                return result;
            }

            int offset = 0;
            int maxPDUDataLength = maxTransmitFragmentSize - RPCPDU.CommonFieldsLength - ResponsePDU.ResponseFieldsLength;
            do
            {
                ResponsePDU responsePDU = new ResponsePDU();
                int pduDataLength = Math.Min(responseBytes.Length - offset, maxPDUDataLength);
                responsePDU.DataRepresentation = requestPDU.DataRepresentation;
                responsePDU.CallID = requestPDU.CallID;
                responsePDU.AllocationHint = (uint)(responseBytes.Length - offset);
                responsePDU.Data = ByteReader.ReadBytes(responseBytes, offset, pduDataLength);
                if (offset == 0)
                {
                    responsePDU.Flags |= PacketFlags.FirstFragment;
                }
                if (offset + pduDataLength == responseBytes.Length)
                {
                    responsePDU.Flags |= PacketFlags.LastFragment;
                }
                result.Add(responsePDU);
                offset += pduDataLength;
            }
            while (offset < responseBytes.Length);

            return result;
        }
    }
}