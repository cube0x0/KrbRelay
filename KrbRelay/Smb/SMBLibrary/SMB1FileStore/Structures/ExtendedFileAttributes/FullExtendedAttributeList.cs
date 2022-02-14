/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// [MS-CIFS] 2.2.1.2.2.1 - SMB_FEA_LIST
    /// </summary>
    public class FullExtendedAttributeList : List<FullExtendedAttribute>
    {
        public FullExtendedAttributeList()
        {
        }

        public FullExtendedAttributeList(byte[] buffer) : this(buffer, 0)
        {
        }

        public FullExtendedAttributeList(byte[] buffer, ref int offset) : this(buffer, offset)
        {
            // [MS-CIFS] length MUST contain the total size of the FEAList field, plus the size of the SizeOfListInBytes field
            int length = (int)LittleEndianConverter.ToUInt32(buffer, offset + 0);
            offset += length;
        }

        public FullExtendedAttributeList(byte[] buffer, int offset)
        {
            // [MS-CIFS] length MUST contain the total size of the FEAList field, plus the size of the SizeOfListInBytes field
            int length = (int)LittleEndianConverter.ToUInt32(buffer, offset);
            int position = offset + 4;
            int eof = offset + length;
            while (position < eof)
            {
                FullExtendedAttribute attribute = new FullExtendedAttribute(buffer, position);
                this.Add(attribute);
                position += attribute.Length;
            }
        }

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[this.Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            WriteBytes(buffer, offset);
            offset += this.Length;
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)Length);
            foreach (FullExtendedAttribute entry in this)
            {
                entry.WriteBytes(buffer, offset);
                offset += entry.Length;
            }
        }

        public int Length
        {
            get
            {
                int length = 4;
                foreach (FullExtendedAttribute entry in this)
                {
                    length += entry.Length;
                }
                return length;
            }
        }
    }
}