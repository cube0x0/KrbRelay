/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.GSSAPI;
using System;
using System.Security.Cryptography;
using Utilities;

namespace SMBLibrary.Authentication.NTLM
{
    /// <returns>null if the account does not exist</returns>
    public delegate string GetUserPassword(string userName);

    public class IndependentNTLMAuthenticationProvider : NTLMAuthenticationProviderBase
    {
        public class AuthContext
        {
            public byte[] ServerChallenge;
            public string DomainName;
            public string UserName;
            public string WorkStation;
            public string OSVersion;
            public byte[] SessionKey;
            public bool IsGuest;

            public AuthContext(byte[] serverChallenge)
            {
                ServerChallenge = serverChallenge;
            }
        }

        // Here is an account of the maximum number of times I have witnessed Windows 7 SP1 attempts to login
        // to a server with the same invalid credentials before displaying a login prompt:
        // Note: The number of login attempts is related to the number of slashes following the server name.
        // \\servername                                    -  8 login attempts
        // \\servername\sharename                          - 29 login attempts
        // \\servername\sharename\dir1                     - 52 login attempts
        // \\servername\sharename\dir1\dir2                - 71 login attempts
        // \\servername\sharename\dir1\dir2\dir3           - 63 login attempts
        // \\servername\sharename\dir1\dir2\dir3\dir4      - 81 login attempts
        // \\servername\sharename\dir1\dir2\dir3\dir4\dir5 - 57 login attempts
        private static readonly int DefaultMaxLoginAttemptsInWindow = 100;

        private static readonly TimeSpan DefaultLoginWindowDuration = new TimeSpan(0, 20, 0);
        private GetUserPassword m_GetUserPassword;
        private LoginCounter m_loginCounter;

        /// <param name="getUserPassword">
        /// The NTLM challenge response will be compared against the provided password.
        /// </param>
        public IndependentNTLMAuthenticationProvider(GetUserPassword getUserPassword) : this(getUserPassword, DefaultMaxLoginAttemptsInWindow, DefaultLoginWindowDuration)
        {
        }

        public IndependentNTLMAuthenticationProvider(GetUserPassword getUserPassword, int maxLoginAttemptsInWindow, TimeSpan loginWindowDuration)
        {
            m_GetUserPassword = getUserPassword;
            m_loginCounter = new LoginCounter(maxLoginAttemptsInWindow, loginWindowDuration);
        }

        public override NTStatus GetChallengeMessage(out object context, byte[] negotiateMessageBytes, out byte[] challengeMessageBytes)
        {
            NegotiateMessage negotiateMessage;
            try
            {
                negotiateMessage = new NegotiateMessage(negotiateMessageBytes);
            }
            catch
            {
                context = null;
                challengeMessageBytes = null;
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            byte[] serverChallenge = GenerateServerChallenge();
            context = new AuthContext(serverChallenge);

            ChallengeMessage challengeMessage = new ChallengeMessage();
            // https://msdn.microsoft.com/en-us/library/cc236691.aspx
            challengeMessage.NegotiateFlags = NegotiateFlags.TargetTypeServer |
                                              NegotiateFlags.TargetInfo |
                                              NegotiateFlags.TargetNameSupplied |
                                              NegotiateFlags.Version;
            // [MS-NLMP] NTLMSSP_NEGOTIATE_NTLM MUST be set in the [..] CHALLENGE_MESSAGE to the client.
            challengeMessage.NegotiateFlags |= NegotiateFlags.NTLMSessionSecurity;

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
            {
                challengeMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
            }
            else if ((negotiateMessage.NegotiateFlags & NegotiateFlags.OEMEncoding) > 0)
            {
                challengeMessage.NegotiateFlags |= NegotiateFlags.OEMEncoding;
            }

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.ExtendedSessionSecurity) > 0)
            {
                challengeMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            }
            else if ((negotiateMessage.NegotiateFlags & NegotiateFlags.LanManagerSessionKey) > 0)
            {
                challengeMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            }

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Sign) > 0)
            {
                // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE,
                // the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE.
                challengeMessage.NegotiateFlags |= NegotiateFlags.Sign;
            }

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Seal) > 0)
            {
                // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE,
                // the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE.
                challengeMessage.NegotiateFlags |= NegotiateFlags.Seal;
            }

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Sign) > 0 ||
                (negotiateMessage.NegotiateFlags & NegotiateFlags.Seal) > 0)
            {
                if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Use56BitEncryption) > 0)
                {
                    // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN with
                    // NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the server MUST return
                    // NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE.
                    challengeMessage.NegotiateFlags |= NegotiateFlags.Use56BitEncryption;
                }
                if ((negotiateMessage.NegotiateFlags & NegotiateFlags.Use128BitEncryption) > 0)
                {
                    // [MS-NLMP] If the client sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE,
                    // the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the CHALLENGE_MESSAGE only if
                    // the client sets NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN.
                    challengeMessage.NegotiateFlags |= NegotiateFlags.Use128BitEncryption;
                }
            }

            if ((negotiateMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            {
                challengeMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;
            }

            challengeMessage.TargetName = Environment.MachineName;
            challengeMessage.ServerChallenge = serverChallenge;
            challengeMessage.TargetInfo = AVPairUtils.GetAVPairSequence(Environment.MachineName, Environment.MachineName);
            challengeMessage.Version = NTLMVersion.Server2003;
            challengeMessageBytes = challengeMessage.GetBytes();
            return NTStatus.SEC_I_CONTINUE_NEEDED;
        }

        public override NTStatus Authenticate(object context, byte[] authenticateMessageBytes)
        {
            AuthenticateMessage message;
            try
            {
                message = new AuthenticateMessage(authenticateMessageBytes);
            }
            catch
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            AuthContext authContext = context as AuthContext;
            if (authContext == null)
            {
                // There are two possible reasons for authContext to be null:
                // 1. We have a bug in our implementation, let's assume that's not the case,
                //    according to [MS-SMB2] 3.3.5.5.1 we aren't allowed to return SEC_E_INVALID_HANDLE anyway.
                // 2. The client sent AuthenticateMessage without sending NegotiateMessage first,
                //    in this case the correct response is SEC_E_INVALID_TOKEN.
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            authContext.DomainName = message.DomainName;
            authContext.UserName = message.UserName;
            authContext.WorkStation = message.WorkStation;
            if (message.Version != null)
            {
                authContext.OSVersion = message.Version.ToString();
            }

            if ((message.NegotiateFlags & NegotiateFlags.Anonymous) > 0)
            {
                if (this.EnableGuestLogin)
                {
                    authContext.IsGuest = true;
                    return NTStatus.STATUS_SUCCESS;
                }
                else
                {
                    return NTStatus.STATUS_LOGON_FAILURE;
                }
            }

            if (!m_loginCounter.HasRemainingLoginAttempts(message.UserName.ToLower()))
            {
                return NTStatus.STATUS_ACCOUNT_LOCKED_OUT;
            }

            string password = m_GetUserPassword(message.UserName);
            if (password == null)
            {
                if (this.EnableGuestLogin)
                {
                    authContext.IsGuest = true;
                    return NTStatus.STATUS_SUCCESS;
                }
                else
                {
                    if (m_loginCounter.HasRemainingLoginAttempts(message.UserName.ToLower(), true))
                    {
                        return NTStatus.STATUS_LOGON_FAILURE;
                    }
                    else
                    {
                        return NTStatus.STATUS_ACCOUNT_LOCKED_OUT;
                    }
                }
            }

            bool success;
            byte[] serverChallenge = authContext.ServerChallenge;
            byte[] sessionBaseKey;
            byte[] keyExchangeKey = null;
            if ((message.NegotiateFlags & NegotiateFlags.ExtendedSessionSecurity) > 0)
            {
                if (AuthenticationMessageUtils.IsNTLMv1ExtendedSessionSecurity(message.LmChallengeResponse))
                {
                    // NTLM v1 Extended Session Security:
                    success = AuthenticateV1Extended(password, serverChallenge, message.LmChallengeResponse, message.NtChallengeResponse);
                    if (success)
                    {
                        // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                        sessionBaseKey = new MD4().GetByteHashFromBytes(NTLMCryptography.NTOWFv1(password));
                        byte[] lmowf = NTLMCryptography.LMOWFv1(password);
                        keyExchangeKey = NTLMCryptography.KXKey(sessionBaseKey, message.NegotiateFlags, message.LmChallengeResponse, serverChallenge, lmowf);
                    }
                }
                else
                {
                    // NTLM v2:
                    success = AuthenticateV2(message.DomainName, message.UserName, password, serverChallenge, message.LmChallengeResponse, message.NtChallengeResponse);
                    if (success)
                    {
                        // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                        byte[] responseKeyNT = NTLMCryptography.NTOWFv2(password, message.UserName, message.DomainName);
                        byte[] ntProofStr = ByteReader.ReadBytes(message.NtChallengeResponse, 0, 16);
                        sessionBaseKey = new HMACMD5(responseKeyNT).ComputeHash(ntProofStr);
                        keyExchangeKey = sessionBaseKey;
                    }
                }
            }
            else
            {
                success = AuthenticateV1(password, serverChallenge, message.LmChallengeResponse, message.NtChallengeResponse);
                if (success)
                {
                    // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                    sessionBaseKey = new MD4().GetByteHashFromBytes(NTLMCryptography.NTOWFv1(password));
                    byte[] lmowf = NTLMCryptography.LMOWFv1(password);
                    keyExchangeKey = NTLMCryptography.KXKey(sessionBaseKey, message.NegotiateFlags, message.LmChallengeResponse, serverChallenge, lmowf);
                }
            }

            if (success)
            {
                // https://msdn.microsoft.com/en-us/library/cc236676.aspx
                // https://blogs.msdn.microsoft.com/openspecification/2010/04/19/ntlm-keys-and-sundry-stuff/
                if ((message.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
                {
                    authContext.SessionKey = RC4.Decrypt(keyExchangeKey, message.EncryptedRandomSessionKey);
                }
                else
                {
                    authContext.SessionKey = keyExchangeKey;
                }
                return NTStatus.STATUS_SUCCESS;
            }
            else
            {
                if (m_loginCounter.HasRemainingLoginAttempts(message.UserName.ToLower(), true))
                {
                    return NTStatus.STATUS_LOGON_FAILURE;
                }
                else
                {
                    return NTStatus.STATUS_ACCOUNT_LOCKED_OUT;
                }
            }
        }

        public override bool DeleteSecurityContext(ref object context)
        {
            context = null;
            return true;
        }

        public override object GetContextAttribute(object context, GSSAttributeName attributeName)
        {
            AuthContext authContext = context as AuthContext;
            if (authContext != null)
            {
                switch (attributeName)
                {
                    case GSSAttributeName.DomainName:
                        return authContext.DomainName;

                    case GSSAttributeName.IsGuest:
                        return authContext.IsGuest;

                    case GSSAttributeName.MachineName:
                        return authContext.WorkStation;

                    case GSSAttributeName.OSVersion:
                        return authContext.OSVersion;

                    case GSSAttributeName.SessionKey:
                        return authContext.SessionKey;

                    case GSSAttributeName.UserName:
                        return authContext.UserName;
                }
            }

            return null;
        }

        private bool EnableGuestLogin
        {
            get
            {
                return (m_GetUserPassword("Guest") == String.Empty);
            }
        }

        /// <summary>
        /// LM v1 / NTLM v1
        /// </summary>
        private static bool AuthenticateV1(string password, byte[] serverChallenge, byte[] lmResponse, byte[] ntResponse)
        {
            byte[] expectedLMResponse = NTLMCryptography.ComputeLMv1Response(serverChallenge, password);
            if (ByteUtils.AreByteArraysEqual(expectedLMResponse, lmResponse))
            {
                return true;
            }

            byte[] expectedNTResponse = NTLMCryptography.ComputeNTLMv1Response(serverChallenge, password);
            return ByteUtils.AreByteArraysEqual(expectedNTResponse, ntResponse);
        }

        /// <summary>
        /// LM v1 / NTLM v1 Extended Session Security
        /// </summary>
        private static bool AuthenticateV1Extended(string password, byte[] serverChallenge, byte[] lmResponse, byte[] ntResponse)
        {
            byte[] clientChallenge = ByteReader.ReadBytes(lmResponse, 0, 8);
            byte[] expectedNTLMv1Response = NTLMCryptography.ComputeNTLMv1ExtendedSessionSecurityResponse(serverChallenge, clientChallenge, password);

            return ByteUtils.AreByteArraysEqual(expectedNTLMv1Response, ntResponse);
        }

        /// <summary>
        /// LM v2 / NTLM v2
        /// </summary>
        private bool AuthenticateV2(string domainName, string accountName, string password, byte[] serverChallenge, byte[] lmResponse, byte[] ntResponse)
        {
            // Note: Linux CIFS VFS 3.10 will send LmChallengeResponse with length of 0 bytes
            if (lmResponse.Length == 24)
            {
                byte[] _LMv2ClientChallenge = ByteReader.ReadBytes(lmResponse, 16, 8);
                byte[] expectedLMv2Response = NTLMCryptography.ComputeLMv2Response(serverChallenge, _LMv2ClientChallenge, password, accountName, domainName);
                if (ByteUtils.AreByteArraysEqual(expectedLMv2Response, lmResponse))
                {
                    return true;
                }
            }

            if (AuthenticationMessageUtils.IsNTLMv2NTResponse(ntResponse))
            {
                byte[] clientNTProof = ByteReader.ReadBytes(ntResponse, 0, 16);
                byte[] clientChallengeStructurePadded = ByteReader.ReadBytes(ntResponse, 16, ntResponse.Length - 16);
                byte[] expectedNTProof = NTLMCryptography.ComputeNTLMv2Proof(serverChallenge, clientChallengeStructurePadded, password, accountName, domainName);

                return ByteUtils.AreByteArraysEqual(clientNTProof, expectedNTProof);
            }
            return false;
        }

        /// <summary>
        /// Generate 8-byte server challenge
        /// </summary>
        private static byte[] GenerateServerChallenge()
        {
            byte[] serverChallenge = new byte[8];
            new Random().NextBytes(serverChallenge);
            return serverChallenge;
        }
    }
}