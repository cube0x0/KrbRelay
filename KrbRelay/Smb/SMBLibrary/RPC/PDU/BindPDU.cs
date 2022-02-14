/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// rpcconn_bind_hdr_t
    /// </summary>
    public class BindPDU : RPCPDU
    {
        public const int BindFieldsFixedLength = 8;

        public ushort MaxTransmitFragmentSize; // max_xmit_frag
        public ushort MaxReceiveFragmentSize; // max_recv_frag
        public uint AssociationGroupID; // assoc_group_id
        public ContextList ContextList;
        public byte[] AuthVerifier;

        public BindPDU() : base()
        {
            PacketType = PacketTypeName.Bind;
            ContextList = new ContextList();
            AuthVerifier = new byte[0];
        }

        public BindPDU(byte[] buffer, int offset) : base(buffer, offset)
        {
            offset += CommonFieldsLength;
            MaxTransmitFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            MaxReceiveFragmentSize = LittleEndianReader.ReadUInt16(buffer, ref offset);
            AssociationGroupID = LittleEndianReader.ReadUInt32(buffer, ref offset);
            ContextList = new ContextList(buffer, offset);
            offset += ContextList.Length;
            AuthVerifier = ByteReader.ReadBytes(buffer, offset, AuthLength);
        }

        public override byte[] GetBytes()
        {
            AuthLength = (ushort)AuthVerifier.Length;
            byte[] buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            int offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxTransmitFragmentSize);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, MaxReceiveFragmentSize);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, AssociationGroupID);
            ContextList.WriteBytes(buffer, ref offset);
            ByteWriter.WriteBytes(buffer, offset, AuthVerifier);

            return buffer;
        }

        public override int Length
        {
            get
            {
                return CommonFieldsLength + BindFieldsFixedLength + ContextList.Length + AuthLength;
            }
        }
    }
}