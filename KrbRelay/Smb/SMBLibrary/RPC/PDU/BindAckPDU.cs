/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// rpcconn_bind_ack_hdr_t
    /// </summary>
    public class BindAckPDU : RPCPDU
    {
        public const int BindAckFieldsFixedLength = 8;

        public ushort MaxTransmitFragmentSize; // max_xmit_frag
        public ushort MaxReceiveFragmentSize; // max_recv_frag
        public uint AssociationGroupID; // assoc_group_id
        public string SecondaryAddress; // sec_addr (port_any_t)

        // Padding (alignment to 4 byte boundary)
        public ResultList ResultList; // p_result_list

        public byte[] AuthVerifier;

        public BindAckPDU() : base()
        {
            PacketType = PacketTypeName.BindAck;
            SecondaryAddress = String.Empty;
            ResultList = new ResultList();
            AuthVerifier = new byte[0];
        }

        public BindAckPDU(byte[] buffer, int offset) : base(buffer, offset)
        {
            int startOffset = offset;
            offset += CommonFieldsLength;
            MaxTransmitFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            MaxReceiveFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            AssociationGroupID = LittleEndianReader.ReadUInt32(buffer, ref offset);
            SecondaryAddress = RPCHelper.ReadPortAddress(buffer, ref offset);
            int padding = (4 - ((offset - startOffset) % 4)) % 4;
            offset += padding;
            ResultList = new ResultList(buffer, offset);
            offset += ResultList.Length;
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override byte[] GetBytes()
        {
            AuthLength = (ushort)AuthVerifier.Length;
            int padding = (4 - ((SecondaryAddress.Length + 3) % 4)) % 4;
            byte[] buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            int offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxTransmitFragmentSize);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxReceiveFragmentSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, AssociationGroupID);
            RPCHelper.WritePortAddress(buffer, ref offset, SecondaryAddress);
            offset += padding;
            ResultList.WriteBytes(buffer, ref offset);
            ByteWriter.WriteBytes(buffer, offset, AuthVerifier);

            return buffer;
        }

        public override int Length
        {
            get
            {
                int padding = (4 - ((SecondaryAddress.Length + 3) % 4)) % 4;
                return CommonFieldsLength + BindAckFieldsFixedLength + SecondaryAddress.Length + 3 + padding + ResultList.Length + AuthLength;
            }
        }
    }
}