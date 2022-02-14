/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary
{
    /// <summary>
    /// [MS-DTYP] SECURITY_DESCRIPTOR
    /// </summary>
    public class SecurityDescriptor
    {
        public const int FixedLength = 20;

        public byte Revision;
        public byte Sbz1;
        public SecurityDescriptorControl Control;

        // uint OffsetOwner;
        // uint OffsetGroup;
        // uint OffsetSacl;
        // uint OffsetDacl;
        public SID OwnerSid;

        public SID GroupSid;
        public ACL Sacl;
        public ACL Dacl;

        public SecurityDescriptor()
        {
            Revision = 0x01;
        }

        public SecurityDescriptor(byte[] buffer, int offset)
        {
            Revision = ByteReader.ReadByte(buffer, ref offset);
            Sbz1 = ByteReader.ReadByte(buffer, ref offset);
            Control = (SecurityDescriptorControl)LittleEndianReader.ReadUInt16(buffer, ref offset);
            uint offsetOwner = LittleEndianReader.ReadUInt32(buffer, ref offset);
            uint offsetGroup = LittleEndianReader.ReadUInt32(buffer, ref offset);
            uint offsetSacl = LittleEndianReader.ReadUInt32(buffer, ref offset);
            uint offsetDacl = LittleEndianReader.ReadUInt32(buffer, ref offset);
            if (offsetOwner != 0)
            {
                OwnerSid = new SID(buffer, (int)offsetOwner);
            }

            if (offsetGroup != 0)
            {
                GroupSid = new SID(buffer, (int)offsetGroup);
            }

            if (offsetSacl != 0)
            {
                Sacl = new ACL(buffer, (int)offsetSacl);
            }

            if (offsetDacl != 0)
            {
                Dacl = new ACL(buffer, (int)offsetDacl);
            }
        }

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            uint offsetOwner = 0;
            uint offsetGroup = 0;
            uint offsetSacl = 0;
            uint offsetDacl = 0;
            int offset = FixedLength;
            if (OwnerSid != null)
            {
                offsetOwner = (uint)offset;
                offset += OwnerSid.Length;
            }

            if (GroupSid != null)
            {
                offsetGroup = (uint)offset;
                offset += GroupSid.Length;
            }

            if (Sacl != null)
            {
                offsetSacl = (uint)offset;
                offset += Sacl.Length;
            }

            if (Dacl != null)
            {
                offsetDacl = (uint)offset;
                offset += Dacl.Length;
            }

            offset = 0;
            ByteWriter.WriteByte(buffer, ref offset, Revision);
            ByteWriter.WriteByte(buffer, ref offset, Sbz1);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, (ushort)Control);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetOwner);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetGroup);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetSacl);
            LittleEndianWriter.WriteUInt32(buffer, ref offset, offsetDacl);
            if (OwnerSid != null)
            {
                OwnerSid.WriteBytes(buffer, ref offset);
            }

            if (GroupSid != null)
            {
                GroupSid.WriteBytes(buffer, ref offset);
            }

            if (Sacl != null)
            {
                Sacl.WriteBytes(buffer, ref offset);
            }

            if (Dacl != null)
            {
                Dacl.WriteBytes(buffer, ref offset);
            }

            return buffer;
        }

        public int Length
        {
            get
            {
                int length = FixedLength;
                if (OwnerSid != null)
                {
                    length += OwnerSid.Length;
                }

                if (GroupSid != null)
                {
                    length += GroupSid.Length;
                }

                if (Sacl != null)
                {
                    length += Sacl.Length;
                }

                if (Dacl != null)
                {
                    length += Dacl.Length;
                }

                return length;
            }
        }
    }
}