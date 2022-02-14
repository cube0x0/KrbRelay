/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 NEGOTIATE Response
    /// </summary>
    public class NegotiateResponse : SMB2Command
    {
        public const int FixedSize = 64;
        public const int DeclaredSize = 65;

        private ushort StructureSize;
        public SecurityMode SecurityMode;
        public SMB2Dialect DialectRevision;
        private ushort NegotiateContextCount;
        public Guid ServerGuid;
        public Capabilities Capabilities;
        public uint MaxTransactSize;
        public uint MaxReadSize;
        public uint MaxWriteSize;
        public DateTime SystemTime;
        public DateTime ServerStartTime;
        private ushort SecurityBufferOffset;
        private ushort SecurityBufferLength;
        private uint NegotiateContextOffset;
        public byte[] SecurityBuffer = new byte[0];
        public List<NegotiateContext> NegotiateContextList = new List<NegotiateContext>();

        public NegotiateResponse() : base(SMB2CommandName.Negotiate)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public NegotiateResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            SecurityMode = (SecurityMode)LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 2);
            DialectRevision = (SMB2Dialect)LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 4);
            NegotiateContextCount = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 6);
            ServerGuid = LittleEndianConverter.ToGuid(buffer, offset + SMB2Header.Length + 8);
            Capabilities = (Capabilities)LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 24);
            MaxTransactSize = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 28);
            MaxReadSize = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 32);
            MaxWriteSize = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 36);
            SystemTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + SMB2Header.Length + 40));
            ServerStartTime = DateTime.FromFileTimeUtc(LittleEndianConverter.ToInt64(buffer, offset + SMB2Header.Length + 48));
            SecurityBufferOffset = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 56);
            SecurityBufferLength = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 58);
            NegotiateContextOffset = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 60);
            SecurityBuffer = ByteReader.ReadBytes(buffer, offset + SecurityBufferOffset, SecurityBufferLength);
            NegotiateContextList = NegotiateContext.ReadNegotiateContextList(buffer, (int)NegotiateContextOffset, NegotiateContextCount);
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            SecurityBufferOffset = 0;
            SecurityBufferLength = (ushort)SecurityBuffer.Length;
            int paddedSecurityBufferLength = (int)Math.Ceiling((double)SecurityBufferLength / 8) * 8;
            if (SecurityBuffer.Length > 0)
            {
                SecurityBufferOffset = SMB2Header.Length + FixedSize;
            }
            NegotiateContextOffset = 0;
            NegotiateContextCount = (ushort)NegotiateContextList.Count;
            if (NegotiateContextList.Count > 0)
            {
                // NegotiateContextList must be 8-byte aligned
                NegotiateContextOffset = (uint)(SMB2Header.Length + FixedSize + paddedSecurityBufferLength);
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, (ushort)SecurityMode);
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, (ushort)DialectRevision);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, NegotiateContextCount);
            LittleEndianWriter.WriteGuid(buffer, offset + 8, ServerGuid);
            LittleEndianWriter.WriteUInt32(buffer, offset + 24, (uint)Capabilities);
            LittleEndianWriter.WriteUInt32(buffer, offset + 28, MaxTransactSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 32, MaxReadSize);
            LittleEndianWriter.WriteUInt32(buffer, offset + 36, MaxWriteSize);
            LittleEndianWriter.WriteInt64(buffer, offset + 40, SystemTime.ToFileTimeUtc());
            LittleEndianWriter.WriteInt64(buffer, offset + 48, ServerStartTime.ToFileTimeUtc());
            LittleEndianWriter.WriteUInt16(buffer, offset + 56, SecurityBufferOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 58, SecurityBufferLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 60, NegotiateContextOffset);
            ByteWriter.WriteBytes(buffer, offset + FixedSize, SecurityBuffer);
            NegotiateContext.WriteNegotiateContextList(buffer, offset + FixedSize + paddedSecurityBufferLength, NegotiateContextList);
        }

        public override int CommandLength
        {
            get
            {
                if (NegotiateContextList.Count == 0)
                {
                    return FixedSize + SecurityBuffer.Length;
                }
                else
                {
                    int paddedSecurityBufferLength = (int)Math.Ceiling((double)SecurityBufferLength / 8) * 8;
                    return FixedSize + paddedSecurityBufferLength + NegotiateContext.GetNegotiateContextListLength(NegotiateContextList);
                }
            }
        }
    }
}