/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// [MS-CIFS] 2.2.1.2.1 - SMB_GEA
    /// </summary>
    public class ExtendedAttributeName
    {
        private byte AttributeNameLengthInBytes;
        public string AttributeName; // ANSI, AttributeNameLengthInBytes + 1 byte null termination

        public ExtendedAttributeName()
        {
        }

        public ExtendedAttributeName(byte[] buffer, int offset)
        {
            AttributeNameLengthInBytes = ByteReader.ReadByte(buffer, offset + 0);
            AttributeName = ByteReader.ReadAnsiString(buffer, offset + 1, AttributeNameLengthInBytes);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            AttributeNameLengthInBytes = (byte)AttributeName.Length;
            ByteWriter.WriteByte(buffer, offset + 0, AttributeNameLengthInBytes);
            ByteWriter.WriteAnsiString(buffer, offset + 1, AttributeName, AttributeName.Length);
        }

        public int Length
        {
            get
            {
                return 1 + AttributeName.Length + 1;
            }
        }
    }
}