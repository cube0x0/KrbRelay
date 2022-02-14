/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Text;

namespace SMBLibrary.RPC
{
    public class NDRUnicodeString : INDRStructure
    {
        private bool m_writeNullTerminationCharacter;

        public string Value;

        public NDRUnicodeString() : this(String.Empty, true)
        {
        }

        public NDRUnicodeString(string value) : this(value, true)
        {
        }

        public NDRUnicodeString(string value, bool writeNullTerminationCharacter)
        {
            m_writeNullTerminationCharacter = writeNullTerminationCharacter;
            Value = value;
        }

        public NDRUnicodeString(NDRParser parser)
        {
            Read(parser);
        }

        // 14.3.4.2 - Conformant and Varying Strings
        public void Read(NDRParser parser)
        {
            uint maxCount = parser.ReadUInt32();
            // the offset from the first index of the string to the first index of the actual subset being passed
            uint index = parser.ReadUInt32();
            // actualCount includes the null terminator
            uint actualCount = parser.ReadUInt32();
            StringBuilder builder = new StringBuilder();
            for (int position = 0; position < actualCount; position++)
            {
                builder.Append((char)parser.ReadUInt16());
            }
            this.Value = builder.ToString().TrimEnd('\0');
        }

        public void Write(NDRWriter writer)
        {
            string valueToWrite = String.Empty;
            if (Value != null)
            {
                valueToWrite = Value;
            }

            if (m_writeNullTerminationCharacter)
            {
                valueToWrite += '\0';
            }

            uint maxCount = (uint)valueToWrite.Length;
            writer.WriteUInt32(maxCount);
            // the offset from the first index of the string to the first index of the actual subset being passed
            uint index = 0;
            writer.WriteUInt32(index);
            uint actualCount = (uint)valueToWrite.Length;
            writer.WriteUInt32(actualCount);
            for (int position = 0; position < valueToWrite.Length; position++)
            {
                writer.WriteUInt16((ushort)valueToWrite[position]);
            }
        }
    }
}