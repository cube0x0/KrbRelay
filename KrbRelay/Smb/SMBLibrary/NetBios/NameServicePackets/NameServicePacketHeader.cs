/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.1.1. HEADER
    /// </summary>
    public class NameServicePacketHeader
    {
        public const int Length = 12;

        public ushort TransactionID;
        public NameServiceOperation OpCode;
        public OperationFlags Flags;
        public byte ResultCode;
        public ushort QDCount;
        public ushort ANCount;
        public ushort NSCount;
        public ushort ARCount;

        public NameServicePacketHeader()
        {
        }

        public NameServicePacketHeader(byte[] buffer, ref int offset) : this(buffer, offset)
        {
            offset += Length;
        }

        public NameServicePacketHeader(byte[] buffer, int offset)
        {
            TransactionID = BigEndianConverter.ToUInt16(buffer, offset + 0);
            ushort temp = BigEndianConverter.ToUInt16(buffer, offset + 2);
            ResultCode = (byte)(temp & 0xF);
            Flags = (OperationFlags)((temp >> 4) & 0x7F);
            OpCode = (NameServiceOperation)((temp >> 11) & 0x1F);
            QDCount = BigEndianConverter.ToUInt16(buffer, offset + 4);
            ANCount = BigEndianConverter.ToUInt16(buffer, offset + 6);
            NSCount = BigEndianConverter.ToUInt16(buffer, offset + 8);
            ARCount = BigEndianConverter.ToUInt16(buffer, offset + 10);
        }

        public void WriteBytes(Stream stream)
        {
            BigEndianWriter.WriteUInt16(stream, TransactionID);
            ushort temp = (ushort)(ResultCode & (0xF));
            temp |= (ushort)((byte)Flags << 4);
            temp |= (ushort)((byte)OpCode << 11);
            BigEndianWriter.WriteUInt16(stream, temp);
            BigEndianWriter.WriteUInt16(stream, QDCount);
            BigEndianWriter.WriteUInt16(stream, ANCount);
            BigEndianWriter.WriteUInt16(stream, NSCount);
            BigEndianWriter.WriteUInt16(stream, ARCount);
        }
    }
}