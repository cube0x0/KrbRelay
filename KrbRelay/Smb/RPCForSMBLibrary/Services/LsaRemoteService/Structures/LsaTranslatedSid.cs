/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.RPC;
using System.Collections.Generic;

namespace SMBLibrary.Services
{
    public class LsaTranslatedSid : INDRStructure
    {
        public LsaSIDNameUse Use;
        public uint RelativeId;
        public uint DomainIndex;

        public void Read(NDRParser parser)
        {
            parser.BeginStructure();
            Use = (LsaSIDNameUse)parser.ReadUInt16();
            RelativeId = parser.ReadUInt32();
            DomainIndex = parser.ReadUInt32();
            parser.EndStructure();
        }

        public void Write(NDRWriter writer)
        {
            writer.BeginStructure();
            writer.WriteUInt16((ushort)Use);
            writer.WriteUInt32(RelativeId);
            writer.WriteUInt32(DomainIndex);
            writer.EndStructure();
        }

        public SID GetSID(SID DomainSID)
        {
            SID sid = new SID();
            sid.Revision = DomainSID.Revision;
            sid.IdentifierAuthority = DomainSID.IdentifierAuthority;
            sid.SubAuthority = new List<uint>(DomainSID.SubAuthority);
            sid.SubAuthority.Add(RelativeId);
            return sid;
        }
    }
}