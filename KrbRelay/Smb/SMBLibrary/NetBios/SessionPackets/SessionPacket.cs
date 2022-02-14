/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.3.1. SESSION PACKET
    /// [MS-SMB2] 2.1 Transport - Direct TCP transport packet
    /// </summary>
    /// <remarks>
    /// We extend this implementation to support Direct TCP transport packet which utilize the unused session packet flags to extend the maximum trailer length.
    /// </remarks>
    public abstract class SessionPacket
    {
        public const int HeaderLength = 4;
        public const int MaxSessionPacketLength = 131075;
        public const int MaxDirectTcpPacketLength = 16777215;

        public SessionPacketTypeName Type;
        private int TrailerLength; // Session packet: 17 bits, Direct TCP transport packet: 3 bytes
        public byte[] Trailer;

        public SessionPacket()
        {
        }

        public SessionPacket(byte[] buffer, int offset)
        {
            Type = (SessionPacketTypeName)ByteReader.ReadByte(buffer, offset + 0);
            TrailerLength = ByteReader.ReadByte(buffer, offset + 1) << 16 | BigEndianConverter.ToUInt16(buffer, offset + 2);
            Trailer = ByteReader.ReadBytes(buffer, offset + 4, TrailerLength);
        }

        public virtual byte[] GetBytes()
        {
            TrailerLength = this.Trailer.Length;

            byte flags = Convert.ToByte(TrailerLength >> 16);

            byte[] buffer = new byte[HeaderLength + Trailer.Length];
            ByteWriter.WriteByte(buffer, 0, (byte)Type);
            ByteWriter.WriteByte(buffer, 1, flags);
            BigEndianWriter.WriteUInt16(buffer, 2, (ushort)(TrailerLength & 0xFFFF));
            ByteWriter.WriteBytes(buffer, 4, Trailer);

            return buffer;
        }

        public virtual int Length
        {
            get
            {
                return HeaderLength + Trailer.Length;
            }
        }

        public static int GetSessionPacketLength(byte[] buffer, int offset)
        {
            int trailerLength = ByteReader.ReadByte(buffer, offset + 1) << 16 | BigEndianConverter.ToUInt16(buffer, offset + 2);
            return 4 + trailerLength;
        }

        public static SessionPacket GetSessionPacket(byte[] buffer, int offset)
        {
            SessionPacketTypeName type = (SessionPacketTypeName)ByteReader.ReadByte(buffer, offset);
            switch (type)
            {
                case SessionPacketTypeName.SessionMessage:
                    return new SessionMessagePacket(buffer, offset);

                case SessionPacketTypeName.SessionRequest:
                    return new SessionRequestPacket(buffer, offset);

                case SessionPacketTypeName.PositiveSessionResponse:
                    return new PositiveSessionResponsePacket(buffer, offset);

                case SessionPacketTypeName.NegativeSessionResponse:
                    return new NegativeSessionResponsePacket(buffer, offset);

                case SessionPacketTypeName.RetargetSessionResponse:
                    return new SessionRetargetResponsePacket(buffer, offset);

                case SessionPacketTypeName.SessionKeepAlive:
                    return new SessionKeepAlivePacket(buffer, offset);

                default:
                    throw new InvalidDataException("Invalid NetBIOS session packet type: 0x" + ((byte)type).ToString("X2"));
            }
        }
    }
}