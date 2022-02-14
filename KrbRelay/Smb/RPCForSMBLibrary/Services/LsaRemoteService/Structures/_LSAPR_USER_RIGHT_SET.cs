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
    public class _LSAPR_USER_RIGHT_SET : INDRStructure
    {
        public uint EntriesRead;
        public NDRConformantArray<LsaUnicodeString> UserRights;

        //public void Read(NDRParser parser)
        //{
        //    parser.BeginStructure();
        //    EntriesRead = parser.ReadUInt32();
        //    UserRights = new NDRConformantArray<LsaUnicodeString>();
        //    parser.ReadEmbeddedStructureFullPointer(ref UserRights);
        //    parser.EndStructure();
        //}
        public void Read(NDRParser parser)
        {
            throw new NotImplementedException();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt32(EntriesRead);
            writer.WriteEmbeddedStructureFullPointer(UserRights);
            writer.EndStructure();
        }
    }
}