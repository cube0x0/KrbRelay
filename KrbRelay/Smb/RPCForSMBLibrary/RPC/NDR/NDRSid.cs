/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.RPC
{
    public class NDRSID : INDRStructure
    {
        private SID sid;

        public NDRSID()
        {
            sid = new SID();
        }

        public NDRSID(SID sid)
        {
            this.sid = sid;
        }

        public void Read(NDRParser parser)
        {
            uint subAuthorityCount = parser.ReadUInt32();
            byte[] buffer = parser.ReadBytes((int)(SID.FixedLength + subAuthorityCount * 4));
            var tempSid = new SID(buffer, 0);
            sid.Revision = tempSid.Revision;
            sid.IdentifierAuthority = tempSid.IdentifierAuthority;
            sid.SubAuthority = tempSid.SubAuthority;
        }

        public void Write(NDRWriter writer)
        {
            byte[] data = new byte[sid.Length];
            int offset = 0;
            sid.WriteBytes(data, ref offset);
            writer.WriteUInt32((uint)sid.SubAuthority.Count);
            writer.WriteBytes(data);
        }
    }
}