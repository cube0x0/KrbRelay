/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.2. SESSION REQUEST PACKET
    /// </summary>
    public class SessionRequestPacket : SessionPacket
    {
        public string CalledName;
        public string CallingName;

        public SessionRequestPacket()
        {
            this.Type = SessionPacketTypeName.SessionRequest;
        }

        public SessionRequestPacket(byte[] buffer, int offset) : base(buffer, offset)
        {
            CalledName = NetBiosUtils.DecodeName(this.Trailer, ref offset);
            CallingName = NetBiosUtils.DecodeName(this.Trailer, ref offset);
        }

        public override byte[] GetBytes()
        {
            byte[] part1 = NetBiosUtils.EncodeName(CalledName, String.Empty);
            byte[] part2 = NetBiosUtils.EncodeName(CallingName, String.Empty);
            this.Trailer = new byte[part1.Length + part2.Length];
            ByteWriter.WriteBytes(this.Trailer, 0, part1);
            ByteWriter.WriteBytes(this.Trailer, part1.Length, part2);
            return base.GetBytes();
        }

        public override int Length
        {
            get
            {
                byte[] part1 = NetBiosUtils.EncodeName(CalledName, String.Empty);
                byte[] part2 = NetBiosUtils.EncodeName(CallingName, String.Empty);
                return HeaderLength + part1.Length + part2.Length;
            }
        }
    }
}