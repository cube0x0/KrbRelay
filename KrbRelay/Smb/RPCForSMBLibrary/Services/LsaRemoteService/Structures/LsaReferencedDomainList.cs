/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System;

namespace SMBLibrary.Services
{
    public class LsaReferencedDomainList : INDRStructure
    {
        public uint Entries;
        public NDRConformantArray<LsaTrustInformation> Names;
        public uint MaxEntries;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            Entries = parser.ReadUInt32();

            Names = new NDRConformantArray<LsaTrustInformation>();
            parser.ReadEmbeddedStructureFullPointer(ref Names);
            MaxEntries = parser.ReadUInt32();
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            throw new NotImplementedException();
            writer.BeginStructure();
            writer.WriteUInt32(Entries);

            writer.WriteEmbeddedStructureFullPointer(Names);
            writer.EndStructure();
        }
    }
}