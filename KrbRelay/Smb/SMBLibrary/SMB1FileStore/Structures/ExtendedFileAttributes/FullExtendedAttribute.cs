/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// [MS-CIFS] 2.2.1.2.2 - SMB_FEA
    /// </summary>
    public class FullExtendedAttribute
    {
        public ExtendedAttributeFlags ExtendedAttributeFlag;
        private byte AttributeNameLengthInBytes;
        private ushort AttributeValueLengthInBytes;
        public string AttributeName; // ANSI, AttributeNameLengthInBytes + 1 byte null termination
        public string AttributeValue; // ANSI

        public FullExtendedAttribute()
        {
        }

        public FullExtendedAttribute(byte[] buffer, int offset)
        {
            ExtendedAttributeFlag = (ExtendedAttributeFlags)ByteReader.ReadByte(buffer, offset);
            AttributeNameLengthInBytes = ByteReader.ReadByte(buffer, offset + 1);
            AttributeValueLengthInBytes = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            AttributeName = ByteReader.ReadAnsiString(buffer, offset + 4, AttributeNameLengthInBytes);
            AttributeValue = ByteReader.ReadAnsiString(buffer, offset + 4 + AttributeNameLengthInBytes + 1, AttributeValueLengthInBytes);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            AttributeNameLengthInBytes = (byte)AttributeName.Length;
            AttributeValueLengthInBytes = (ushort)AttributeValue.Length;
            ByteWriter.WriteByte(buffer, offset, (byte)ExtendedAttributeFlag);
            ByteWriter.WriteByte(buffer, offset + 1, AttributeNameLengthInBytes);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, AttributeValueLengthInBytes);
            ByteWriter.WriteAnsiString(buffer, offset + 4, AttributeName, AttributeName.Length);
            ByteWriter.WriteAnsiString(buffer, offset + 4 + AttributeNameLengthInBytes + 1, AttributeValue, AttributeValue.Length);
        }

        public int Length
        {
            get
            {
                return 4 + AttributeName.Length + 1 + AttributeValue.Length;
            }
        }
    }
}