/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// rpcconn_bind_nak_hdr_t
    /// </summary>
    public class BindNakPDU : RPCPDU
    {
        public const int BindNakFieldsFixedLength = 2;

        public RejectionReason RejectReason; // provider_reject_reason
        public VersionsSupported Versions; // versions

        public BindNakPDU() : base()
        {
            PacketType = PacketTypeName.BindNak;
        }

        public BindNakPDU(byte[] buffer, int offset) : base(buffer, offset)
        {
            int startOffset = offset;
            offset += CommonFieldsLength;
            RejectReason = (RejectionReason)LittleEndianReader.ReadUInt16(buffer, ref offset);
            Versions = new VersionsSupported(buffer, offset);
        }

        public override byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            WriteCommonFieldsBytes(buffer);
            int offset = CommonFieldsLength;
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)RejectReason);
            Versions.WriteBytes(buffer, offset);

            return buffer;
        }

        public override int Length
        {
            get
            {
                int length = CommonFieldsLength + BindNakFieldsFixedLength;
                if (Versions != null)
                {
                    length += Versions.Length;
                }
                return length;
            }
        }
    }
}