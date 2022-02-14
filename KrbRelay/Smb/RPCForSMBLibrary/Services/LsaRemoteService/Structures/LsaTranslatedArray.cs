/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;

namespace SMBLibrary.Services
{
    public class LsaTranslatedArray<T> : INDRStructure where T : INDRStructure, new()
    {
        public NDRConformantArray<T> Items;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            uint itemCount = parser.ReadUInt32();
            parser.ReadEmbeddedStructureFullPointer(ref Items);
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32((uint)(Items == null ? 0 : Items.Count));

            writer.WriteEmbeddedStructureFullPointer(Items);
            writer.EndStructure();
        }
    }
}