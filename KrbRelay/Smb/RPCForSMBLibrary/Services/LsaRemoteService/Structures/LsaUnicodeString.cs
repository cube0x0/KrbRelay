/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class LsaUnicodeString : INDRStructure
    {
        private NDRUnicodeString buffer;
        private uint lenght;
        private uint size;

        public LsaUnicodeString()
        {
            buffer = new NDRUnicodeString(string.Empty, false);
        }

        public LsaUnicodeString(string value)
        {
            buffer = new NDRUnicodeString(value, false);
        }

        public LsaUnicodeString(NDRParser parser) : this()
        {
            Read(parser);
        }

        public string Value
        {
            get
            {
                return buffer.Value;
            }
            set
            {
                buffer.Value = value;
            }
        }

        public void Read(NDRParser parser)
        {
            lenght = parser.ReadUInt16();
            size = parser.ReadUInt16();
            parser.ReadEmbeddedStructureFullPointer(ref buffer);
        }

        public void Write(NDRWriter writer)
        {
            ushort length = 0;
            if (buffer.Value != null)
            {
                length = (ushort)buffer.Value.Length;
            }

            writer.WriteUInt16((ushort)(length * 2));
            writer.WriteUInt16((ushort)((length) * 2));

            writer.WriteEmbeddedStructureFullPointer(buffer);
        }
    }
}