/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.1.3. RESOURCE RECORD
    /// </summary>
    public class ResourceRecord
    {
        public string Name;
        public NameRecordType Type;
        public ResourceRecordClass Class;
        public uint TTL;

        // ushort DataLength
        public byte[] Data;

        public ResourceRecord(NameRecordType type)
        {
            Name = String.Empty;
            Type = type;
            Class = ResourceRecordClass.In;
            TTL = (uint)new TimeSpan(7, 0, 0, 0).TotalSeconds;
            Data = new byte[0];
        }

        public ResourceRecord(byte[] buffer, ref int offset)
        {
            Name = NetBiosUtils.DecodeName(buffer, ref offset);
            Type = (NameRecordType)BigEndianReader.ReadUInt16(buffer, ref offset);
            Class = (ResourceRecordClass)BigEndianReader.ReadUInt16(buffer, ref offset);
            TTL = BigEndianReader.ReadUInt32(buffer, ref offset);
            ushort dataLength = BigEndianReader.ReadUInt16(buffer, ref offset);
            Data = ByteReader.ReadBytes(buffer, ref offset, dataLength);
        }

        public void WriteBytes(Stream stream)
        {
            WriteBytes(stream, null);
        }

        public void WriteBytes(Stream stream, int? nameOffset)
        {
            if (nameOffset.HasValue)
            {
                NetBiosUtils.WriteNamePointer(stream, nameOffset.Value);
            }
            else
            {
                byte[] encodedName = NetBiosUtils.EncodeName(Name, String.Empty);
                ByteWriter.WriteBytes(stream, encodedName);
            }
            BigEndianWriter.WriteUInt16(stream, (ushort)Type);
            BigEndianWriter.WriteUInt16(stream, (ushort)Class);
            BigEndianWriter.WriteUInt32(stream, TTL);
            BigEndianWriter.WriteUInt16(stream, (ushort)Data.Length);
            ByteWriter.WriteBytes(stream, Data);
        }
    }
}