/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.3. POSITIVE SESSION RESPONSE PACKET
    /// </summary>
    public class PositiveSessionResponsePacket : SessionPacket
    {
        public PositiveSessionResponsePacket() : base()
        {
            this.Type = SessionPacketTypeName.PositiveSessionResponse;
        }

        public PositiveSessionResponsePacket(byte[] buffer, int offset) : base(buffer, offset)
        {
        }

        public override byte[] GetBytes()
        {
            this.Trailer = new byte[0];
            return base.GetBytes();
        }

        public override int Length
        {
            get
            {
                return HeaderLength;
            }
        }
    }
}