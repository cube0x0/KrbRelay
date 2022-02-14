/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// [MS-CIFS] 2.2.1.2.1.1 - SMB_GEA_LIST
    /// </summary>
    public class ExtendedAttributeNameList : List<ExtendedAttributeName>
    {
        public ExtendedAttributeNameList()
        {
        }

        public ExtendedAttributeNameList(byte[] buffer, int offset)
        {
            // [MS-CIFS] length MUST contain the total size of the GEAList field, plus the size of the SizeOfListInBytes field
            int length = (int)LittleEndianConverter.ToUInt32(buffer, offset + 0);
            int position = offset + 4;
            int eof = offset + length;
            while (position < eof)
            {
                ExtendedAttributeName attribute = new ExtendedAttributeName(buffer, position);
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

        public void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, ref offset, (uint)Length);
            foreach (ExtendedAttributeName entry in this)
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
                foreach (ExtendedAttributeName entry in this)
                {
                    length += entry.Length;
                }
                return length;
            }
        }
    }
}