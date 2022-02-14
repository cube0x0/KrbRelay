/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-FSCC] 2.3.31 - FSCTL_PIPE_WAIT Request
    /// </summary>
    public class PipeWaitRequest
    {
        public const int FixedLength = 14;

        public ulong Timeout;
        private uint NameLength;
        public bool TimeSpecified;
        public byte Padding;
        public string Name;

        public PipeWaitRequest()
        {
        }

        public PipeWaitRequest(byte[] buffer, int offset)
        {
            Timeout = LittleEndianConverter.ToUInt64(buffer, offset + 0);
            NameLength = LittleEndianConverter.ToUInt32(buffer, offset + 8);
            TimeSpecified = Convert.ToBoolean(ByteReader.ReadByte(buffer, offset + 12));
            Padding = ByteReader.ReadByte(buffer, offset + 13);
            Name = ByteReader.ReadUTF16String(buffer, offset + 14, (int)(NameLength / 2));
        }

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            LittleEndianWriter.WriteUInt64(buffer, 0, Timeout);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)(Name.Length * 2));
            ByteWriter.WriteByte(buffer, 12, Convert.ToByte(TimeSpecified));
            ByteWriter.WriteByte(buffer, 13, Padding);
            ByteWriter.WriteUTF16String(buffer, 14, Name);
            return buffer;
        }

        public int Length
        {
            get
            {
                return FixedLength + Name.Length * 2;
            }
        }
    }
}