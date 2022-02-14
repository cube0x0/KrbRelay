/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.5. SESSION RETARGET RESPONSE PACKET
    /// </summary>
    public class SessionRetargetResponsePacket : SessionPacket
    {
        private uint IPAddress;
        private ushort Port;

        public SessionRetargetResponsePacket() : base()
        {
            this.Type = SessionPacketTypeName.RetargetSessionResponse;
        }

        public SessionRetargetResponsePacket(byte[] buffer, int offset) : base(buffer, offset)
        {
            IPAddress = BigEndianConverter.ToUInt32(this.Trailer, offset + 0);
            Port = BigEndianConverter.ToUInt16(this.Trailer, offset + 4);
        }

        public override byte[] GetBytes()
        {
            this.Trailer = new byte[6];
            BigEndianWriter.WriteUInt32(this.Trailer, 0, IPAddress);
            BigEndianWriter.WriteUInt16(this.Trailer, 4, Port);
            return base.GetBytes();
        }

        public override int Length
        {
            get
            {
                return HeaderLength + 6;
            }
        }
    }
}