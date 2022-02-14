/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    public abstract class SimpleProtectedNegotiationToken
    {
        public const byte ApplicationTag = 0x60;

        public static readonly byte[] SPNEGOIdentifier = new byte[] { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02 };

        public abstract byte[] GetBytes();

        /// <param name="includeHeader">Prepend the generic GSSAPI header. Required for negTokenInit, optional for negTokenResp.</param>
        public byte[] GetBytes(bool includeHeader)
        {
            byte[] tokenBytes = this.GetBytes();
            if (includeHeader)
            {
                int objectIdentifierFieldSize = DerEncodingHelper.GetLengthFieldSize(SPNEGOIdentifier.Length);
                int tokenLength = 1 + objectIdentifierFieldSize + SPNEGOIdentifier.Length + tokenBytes.Length;
                int tokenLengthFieldSize = DerEncodingHelper.GetLengthFieldSize(tokenLength);
                int headerLength = 1 + tokenLengthFieldSize + 1 + objectIdentifierFieldSize + SPNEGOIdentifier.Length;
                byte[] buffer = new byte[headerLength + tokenBytes.Length];
                int offset = 0;
                ByteWriter.WriteByte(buffer, ref offset, ApplicationTag);
                DerEncodingHelper.WriteLength(buffer, ref offset, tokenLength);
                ByteWriter.WriteByte(buffer, ref offset, (byte)DerEncodingTag.ObjectIdentifier);
                DerEncodingHelper.WriteLength(buffer, ref offset, SPNEGOIdentifier.Length);
                ByteWriter.WriteBytes(buffer, ref offset, SPNEGOIdentifier);
                ByteWriter.WriteBytes(buffer, ref offset, tokenBytes);
                return buffer;
            }
            else
            {
                return tokenBytes;
            }
        }

        /// <summary>
        /// https://tools.ietf.org/html/rfc2743
        /// </summary>
        /// <exception cref="System.IO.InvalidDataException"></exception>
        public static SimpleProtectedNegotiationToken ReadToken(byte[] tokenBytes, int offset, bool serverInitiatedNegotiation)
        {
            byte tag = ByteReader.ReadByte(tokenBytes, ref offset);
            if (tag == ApplicationTag)
            {
                // https://msdn.microsoft.com/en-us/library/ms995330.aspx
                // when an InitToken is sent, it is prepended by an Application Constructed Object specifier (0x60),
                // and the OID for SPNEGO. This is the generic GSSAPI header.

                // [RFC 2743] The use of the Mechanism-Independent Token Format is required for initial context
                // establishment tokens, use in non-initial tokens is optional.
                int tokenLength = DerEncodingHelper.ReadLength(tokenBytes, ref offset);
                tag = ByteReader.ReadByte(tokenBytes, ref offset);
                if (tag == (byte)DerEncodingTag.ObjectIdentifier)
                {
                    int objectIdentifierLength = DerEncodingHelper.ReadLength(tokenBytes, ref offset);
                    byte[] objectIdentifier = ByteReader.ReadBytes(tokenBytes, ref offset, objectIdentifierLength);
                    if (ByteUtils.AreByteArraysEqual(objectIdentifier, SPNEGOIdentifier))
                    {
                        tag = ByteReader.ReadByte(tokenBytes, ref offset);
                        if (tag == SimpleProtectedNegotiationTokenInit.NegTokenInitTag)
                        {
                            if (serverInitiatedNegotiation)
                            {
                                // [MS-SPNG] Standard GSS has a strict notion of client (initiator) and server (acceptor).
                                // If the client has not sent a negTokenInit ([RFC4178] section 4.2.1) message, no context establishment token is expected from the server.
                                // The [NegTokenInit2] SPNEGO extension allows the server to generate a context establishment token message [..] and send it to the client.
                                return new SimpleProtectedNegotiationTokenInit2(tokenBytes, offset);
                            }
                            else
                            {
                                return new SimpleProtectedNegotiationTokenInit(tokenBytes, offset);
                            }
                        }
                        else if (tag == SimpleProtectedNegotiationTokenResponse.NegTokenRespTag)
                        {
                            return new SimpleProtectedNegotiationTokenResponse(tokenBytes, offset);
                        }
                    }
                }
            }
            else if (tag == SimpleProtectedNegotiationTokenResponse.NegTokenRespTag)
            {
                return new SimpleProtectedNegotiationTokenResponse(tokenBytes, offset);
            }
            return null;
        }
    }
}