/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class LsaTranslatedName : INDRStructure
    {
        private LsaUnicodeString unicode_string = new LsaUnicodeString();

        public LsaSIDNameUse Use;
        public uint DomainIndex;

        public string Name
        {
            get
            {
                return unicode_string.Value;
            }
            set
            {
                unicode_string.Value = value;
            }
        }

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            Use = (LsaSIDNameUse)parser.ReadUInt32();

            parser.ReadStructure(unicode_string);
            DomainIndex = parser.ReadUInt32();
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt16((ushort)Use);
            //TODO verifty
            writer.WriteStructure(unicode_string);
            writer.WriteUInt32(DomainIndex);
            writer.EndStructure();
        }
    }
}