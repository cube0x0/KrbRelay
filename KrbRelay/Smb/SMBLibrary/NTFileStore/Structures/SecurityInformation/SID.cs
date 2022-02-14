/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-DTYP] 2.4.2.2 - SID (Packet Representation)
    /// </summary>
    public class SID
    {
        public static readonly byte[] WORLD_SID_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        public static readonly byte[] LOCAL_SID_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
        public static readonly byte[] CREATOR_SID_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };
        public static readonly byte[] SECURITY_NT_AUTHORITY = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

        public const int FixedLength = 8;

        public byte Revision;

        // byte SubAuthorityCount;
        public byte[] IdentifierAuthority; // 6 bytes

        public List<uint> SubAuthority = new List<uint>();

        public SID()
        {
            Revision = 0x01;
        }

        public SID(byte[] buffer, int offset)
        {
            Revision = ByteReader.ReadByte(buffer, ref offset);
            byte subAuthorityCount = ByteReader.ReadByte(buffer, ref offset);
            IdentifierAuthority = ByteReader.ReadBytes(buffer, ref offset, 6);
            for (int index = 0; index < subAuthorityCount; index++)
            {
                uint entry = LittleEndianReader.ReadUInt32(buffer, ref offset);
                SubAuthority.Add(entry);
            }
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            byte subAuthorityCount = (byte)SubAuthority.Count;
            ByteWriter.WriteByte(buffer, ref offset, Revision);
            ByteWriter.WriteByte(buffer, ref offset, subAuthorityCount);
            ByteWriter.WriteBytes(buffer, ref offset, IdentifierAuthority, 6);
            for (int index = 0; index < SubAuthority.Count; index++)
            {
                LittleEndianWriter.WriteUInt32(buffer, ref offset, SubAuthority[index]);
            }
        }

        public int Length
        {
            get
            {
                return FixedLength + SubAuthority.Count * 4;
            }
        }

        public static SID Everyone
        {
            get
            {
                SID sid = new SID();
                sid.IdentifierAuthority = WORLD_SID_AUTHORITY;
                sid.SubAuthority.Add(0);
                return sid;
            }
        }

        public static SID LocalSystem
        {
            get
            {
                SID sid = new SID();
                sid.IdentifierAuthority = SECURITY_NT_AUTHORITY;
                sid.SubAuthority.Add(18);
                return sid;
            }
        }
    }
}