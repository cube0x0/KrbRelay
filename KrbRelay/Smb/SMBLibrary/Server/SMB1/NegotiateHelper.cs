/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using SMBLibrary.SMB1;
using System;

namespace SMBLibrary.Server.SMB1
{
    /// <summary>
    /// Negotiate helper
    /// </summary>
    internal class NegotiateHelper
    {
        public const ushort ServerMaxMpxCount = 50;
        public const ushort ServerNumberVcs = 1;
        public const ushort ServerMaxBufferSize = 65535;
        public const uint ServerMaxRawSize = 65536;

        internal static NegotiateResponse GetNegotiateResponse(SMB1Header header, NegotiateRequest request, GSSProvider securityProvider, ConnectionState state)
        {
            NegotiateResponse response = new NegotiateResponse();

            response.DialectIndex = (ushort)request.Dialects.IndexOf(SMBServer.NTLanManagerDialect);
            response.SecurityMode = SecurityMode.UserSecurityMode | SecurityMode.EncryptPasswords;
            response.MaxMpxCount = ServerMaxMpxCount;
            response.MaxNumberVcs = ServerNumberVcs;
            response.MaxBufferSize = ServerMaxBufferSize;
            response.MaxRawSize = ServerMaxRawSize;
            response.Capabilities = Capabilities.Unicode |
                                    Capabilities.LargeFiles |
                                    Capabilities.NTSMB |
                                    Capabilities.RpcRemoteApi |
                                    Capabilities.NTStatusCode |
                                    Capabilities.NTFind |
                                    Capabilities.InfoLevelPassthrough |
                                    Capabilities.LargeRead |
                                    Capabilities.LargeWrite;
            response.SystemTime = DateTime.UtcNow;
            response.ServerTimeZone = (short)-TimeZone.CurrentTimeZone.GetUtcOffset(DateTime.Now).TotalMinutes;
            NegotiateMessage negotiateMessage = CreateNegotiateMessage();
            ChallengeMessage challengeMessage;
            NTStatus status = securityProvider.GetNTLMChallengeMessage(out state.AuthenticationContext, negotiateMessage, out challengeMessage);
            if (status == NTStatus.SEC_I_CONTINUE_NEEDED)
            {
                response.Challenge = challengeMessage.ServerChallenge;
            }
            response.DomainName = String.Empty;
            response.ServerName = String.Empty;

            return response;
        }

        internal static NegotiateResponseExtended GetNegotiateResponseExtended(NegotiateRequest request, Guid serverGuid)
        {
            NegotiateResponseExtended response = new NegotiateResponseExtended();
            response.DialectIndex = (ushort)request.Dialects.IndexOf(SMBServer.NTLanManagerDialect);
            response.SecurityMode = SecurityMode.UserSecurityMode | SecurityMode.EncryptPasswords;
            response.MaxMpxCount = ServerMaxMpxCount;
            response.MaxNumberVcs = ServerNumberVcs;
            response.MaxBufferSize = ServerMaxBufferSize;
            response.MaxRawSize = ServerMaxRawSize;
            response.Capabilities = Capabilities.Unicode |
                                    Capabilities.LargeFiles |
                                    Capabilities.NTSMB |
                                    Capabilities.RpcRemoteApi |
                                    Capabilities.NTStatusCode |
                                    Capabilities.NTFind |
                                    Capabilities.InfoLevelPassthrough |
                                    Capabilities.LargeRead |
                                    Capabilities.LargeWrite |
                                    Capabilities.ExtendedSecurity;
            response.SystemTime = DateTime.UtcNow;
            response.ServerTimeZone = (short)-TimeZone.CurrentTimeZone.GetUtcOffset(DateTime.Now).TotalMinutes;
            response.ServerGuid = serverGuid;

            return response;
        }

        private static NegotiateMessage CreateNegotiateMessage()
        {
            NegotiateMessage negotiateMessage = new NegotiateMessage();
            negotiateMessage.NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                              NegotiateFlags.OEMEncoding |
                                              NegotiateFlags.Sign |
                                              NegotiateFlags.LanManagerSessionKey |
                                              NegotiateFlags.NTLMSessionSecurity |
                                              NegotiateFlags.AlwaysSign |
                                              NegotiateFlags.Version |
                                              NegotiateFlags.Use128BitEncryption |
                                              NegotiateFlags.Use56BitEncryption;
            negotiateMessage.Version = NTLMVersion.Server2003;
            return negotiateMessage;
        }
    }
}