/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    /// <summary>
    /// [MS-NLMP] NEGOTIATE_MESSAGE (Type 1 Message)
    /// </summary>
    public class NegotiateMessage
    {
        public string Signature; // 8 bytes
        public MessageTypeName MessageType;
        public NegotiateFlags NegotiateFlags;
        public string DomainName;
        public string Workstation;
        public NTLMVersion Version;

        public NegotiateMessage()
        {
            Signature = AuthenticateMessage.ValidSignature;
            MessageType = MessageTypeName.Negotiate;
            DomainName = String.Empty;
            Workstation = String.Empty;
        }

        public NegotiateMessage(byte[] buffer)
        {
            Signature = ByteReader.ReadAnsiString(buffer, 0, 8);
            MessageType = (MessageTypeName)LittleEndianConverter.ToUInt32(buffer, 8);
            NegotiateFlags = (NegotiateFlags)LittleEndianConverter.ToUInt32(buffer, 12);
            DomainName = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 16);
            Workstation = AuthenticationMessageUtils.ReadAnsiStringBufferPointer(buffer, 24);
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version = new NTLMVersion(buffer, 32);
            }
        }

        public byte[] GetBytes()
        {
            if ((NegotiateFlags & NegotiateFlags.DomainNameSupplied) == 0)
            {
                DomainName = String.Empty;
            }

            if ((NegotiateFlags & NegotiateFlags.WorkstationNameSupplied) == 0)
            {
                Workstation = String.Empty;
            }

            int fixedLength = 32;
            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                fixedLength += 8;
            }
            int payloadLength = DomainName.Length * 2 + Workstation.Length * 2;
            byte[] buffer = new byte[fixedLength + payloadLength];
            ByteWriter.WriteAnsiString(buffer, 0, AuthenticateMessage.ValidSignature, 8);
            LittleEndianWriter.WriteUInt32(buffer, 8, (uint)MessageType);
            LittleEndianWriter.WriteUInt32(buffer, 12, (uint)NegotiateFlags);

            if ((NegotiateFlags & NegotiateFlags.Version) > 0)
            {
                Version.WriteBytes(buffer, 32);
            }

            int offset = fixedLength;
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 16, (ushort)(DomainName.Length * 2), (uint)offset);
            ByteWriter.WriteUTF16String(buffer, ref offset, DomainName);
            AuthenticationMessageUtils.WriteBufferPointer(buffer, 24, (ushort)(Workstation.Length * 2), (uint)offset);
            ByteWriter.WriteUTF16String(buffer, ref offset, Workstation);

            return buffer;
        }
    }
}