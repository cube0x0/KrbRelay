/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.GSSAPI;
using SMBLibrary.Authentication.NTLM;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Utilities;

namespace SMBLibrary.Client
{
    public class NTLMAuthenticationHelper
    {
        public static byte[] GetNegotiateMessage(byte[] securityBlob, string domainName, AuthenticationMethod authenticationMethod)
        {
            bool useGSSAPI = false;
            if (securityBlob.Length > 0)
            {
                SimpleProtectedNegotiationTokenInit inputToken = null;
                try
                {
                    inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, true) as SimpleProtectedNegotiationTokenInit;
                }
                catch
                {
                }

                if (inputToken == null || !ContainsMechanism(inputToken, GSSProvider.NTLMSSPIdentifier))
                {
                    return null;
                }
                useGSSAPI = true;
            }

            NegotiateMessage negotiateMessage = new NegotiateMessage();
            negotiateMessage.NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                              NegotiateFlags.OEMEncoding |
                                              NegotiateFlags.Sign |
                                              NegotiateFlags.NTLMSessionSecurity |
                                              NegotiateFlags.DomainNameSupplied |
                                              NegotiateFlags.WorkstationNameSupplied |
                                              NegotiateFlags.AlwaysSign |
                                              NegotiateFlags.Version |
                                              NegotiateFlags.Use128BitEncryption |
                                              NegotiateFlags.KeyExchange |
                                              NegotiateFlags.Use56BitEncryption;

            if (authenticationMethod == AuthenticationMethod.NTLMv1)
            {
                negotiateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            }
            else
            {
                negotiateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            }

            negotiateMessage.Version = NTLMVersion.Server2003;
            negotiateMessage.DomainName = domainName;
            negotiateMessage.Workstation = Environment.MachineName;
            if (useGSSAPI)
            {
                SimpleProtectedNegotiationTokenInit outputToken = new SimpleProtectedNegotiationTokenInit();
                outputToken.MechanismTypeList = new List<byte[]>();
                outputToken.MechanismTypeList.Add(GSSProvider.NTLMSSPIdentifier);
                outputToken.MechanismToken = negotiateMessage.GetBytes();
                return outputToken.GetBytes(true);
            }
            else
            {
                return negotiateMessage.GetBytes();
            }
        }
        
        public static byte[] GetNegotiateMessage(byte[] securityBlob)
        {
            bool useGSSAPI = false;
            if (securityBlob.Length > 0)
            {
                SimpleProtectedNegotiationTokenInit inputToken = null;
                try
                {
                    inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, true) as SimpleProtectedNegotiationTokenInit;
                }
                catch
                {
                }

                if (inputToken == null || !ContainsMechanism(inputToken, GSSProvider.NTLMSSPIdentifier))
                {
                    return null;
                }
                useGSSAPI = true;
            }

            NegotiateMessage negotiateMessage = new NegotiateMessage();
            negotiateMessage.NegotiateFlags = NegotiateFlags.UnicodeEncoding |
                                              NegotiateFlags.OEMEncoding |
                                              NegotiateFlags.Sign |
                                              NegotiateFlags.NTLMSessionSecurity |
                                              NegotiateFlags.DomainNameSupplied |
                                              NegotiateFlags.WorkstationNameSupplied |
                                              NegotiateFlags.AlwaysSign |
                                              NegotiateFlags.Version |
                                              NegotiateFlags.Use128BitEncryption |
                                              NegotiateFlags.KeyExchange |
                                              NegotiateFlags.Use56BitEncryption;

            negotiateMessage.Version = NTLMVersion.Server2003;
            negotiateMessage.Workstation = Environment.MachineName;
            if (useGSSAPI)
            {
                SimpleProtectedNegotiationTokenInit outputToken = new SimpleProtectedNegotiationTokenInit();
                outputToken.MechanismTypeList = new List<byte[]>();
                outputToken.MechanismTypeList.Add(GSSProvider.NTLMSSPIdentifier);
                outputToken.MechanismToken = negotiateMessage.GetBytes();
                return outputToken.GetBytes(true);
            }
            else
            {
                return negotiateMessage.GetBytes();
            }
        }

        public static byte[] GetAuthenticateMessage(byte[] securityBlob, string domainName, string userName, string password, AuthenticationMethod authenticationMethod, out byte[] sessionKey)
        {
            sessionKey = null;
            bool useGSSAPI = false;
            SimpleProtectedNegotiationTokenResponse inputToken = null;
            try
            {
                inputToken = SimpleProtectedNegotiationToken.ReadToken(securityBlob, 0, false) as SimpleProtectedNegotiationTokenResponse;
            }
            catch
            {
            }

            ChallengeMessage challengeMessage;
            if (inputToken != null)
            {
                challengeMessage = GetChallengeMessage(inputToken.ResponseToken);
                useGSSAPI = true;
            }
            else
            {
                challengeMessage = GetChallengeMessage(securityBlob);
            }

            if (challengeMessage == null)
            {
                return null;
            }

            DateTime time = DateTime.UtcNow;
            byte[] clientChallenge = new byte[8];
            new Random().NextBytes(clientChallenge);

            AuthenticateMessage authenticateMessage = new AuthenticateMessage();
            // https://msdn.microsoft.com/en-us/library/cc236676.aspx
            authenticateMessage.NegotiateFlags = NegotiateFlags.Sign |
                                                 NegotiateFlags.NTLMSessionSecurity |
                                                 NegotiateFlags.AlwaysSign |
                                                 NegotiateFlags.Version |
                                                 NegotiateFlags.Use128BitEncryption |
                                                 NegotiateFlags.Use56BitEncryption;
            if ((challengeMessage.NegotiateFlags & NegotiateFlags.UnicodeEncoding) > 0)
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.UnicodeEncoding;
            }
            else
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.OEMEncoding;
            }

            if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.KeyExchange;
            }

            if (authenticationMethod == AuthenticationMethod.NTLMv1)
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.LanManagerSessionKey;
            }
            else
            {
                authenticateMessage.NegotiateFlags |= NegotiateFlags.ExtendedSessionSecurity;
            }

            authenticateMessage.UserName = userName;
            authenticateMessage.DomainName = domainName;
            authenticateMessage.WorkStation = Environment.MachineName;
            byte[] sessionBaseKey;
            byte[] keyExchangeKey;
            if (authenticationMethod == AuthenticationMethod.NTLMv1 || authenticationMethod == AuthenticationMethod.NTLMv1ExtendedSessionSecurity)
            {
                if (authenticationMethod == AuthenticationMethod.NTLMv1)
                {
                    authenticateMessage.LmChallengeResponse = NTLMCryptography.ComputeLMv1Response(challengeMessage.ServerChallenge, password);
                    authenticateMessage.NtChallengeResponse = NTLMCryptography.ComputeNTLMv1Response(challengeMessage.ServerChallenge, password);
                }
                else // NTLMv1ExtendedSessionSecurity
                {
                    authenticateMessage.LmChallengeResponse = ByteUtils.Concatenate(clientChallenge, new byte[16]);
                    authenticateMessage.NtChallengeResponse = NTLMCryptography.ComputeNTLMv1ExtendedSessionSecurityResponse(challengeMessage.ServerChallenge, clientChallenge, password);
                }
                // https://msdn.microsoft.com/en-us/library/cc236699.aspx
                sessionBaseKey = new MD4().GetByteHashFromBytes(NTLMCryptography.NTOWFv1(password));
                byte[] lmowf = NTLMCryptography.LMOWFv1(password);
                keyExchangeKey = NTLMCryptography.KXKey(sessionBaseKey, authenticateMessage.NegotiateFlags, authenticateMessage.LmChallengeResponse, challengeMessage.ServerChallenge, lmowf);
            }
            else // NTLMv2
            {
                NTLMv2ClientChallenge clientChallengeStructure = new NTLMv2ClientChallenge(time, clientChallenge, challengeMessage.TargetInfo);
                byte[] clientChallengeStructurePadded = clientChallengeStructure.GetBytesPadded();
                byte[] ntProofStr = NTLMCryptography.ComputeNTLMv2Proof(challengeMessage.ServerChallenge, clientChallengeStructurePadded, password, userName, domainName);

                authenticateMessage.LmChallengeResponse = NTLMCryptography.ComputeLMv2Response(challengeMessage.ServerChallenge, clientChallenge, password, userName, challengeMessage.TargetName);
                authenticateMessage.NtChallengeResponse = ByteUtils.Concatenate(ntProofStr, clientChallengeStructurePadded);

                // https://msdn.microsoft.com/en-us/library/cc236700.aspx
                byte[] responseKeyNT = NTLMCryptography.NTOWFv2(password, userName, domainName);
                sessionBaseKey = new HMACMD5(responseKeyNT).ComputeHash(ntProofStr);
                keyExchangeKey = sessionBaseKey;
            }
            authenticateMessage.Version = NTLMVersion.Server2003;

            // https://msdn.microsoft.com/en-us/library/cc236676.aspx
            if ((challengeMessage.NegotiateFlags & NegotiateFlags.KeyExchange) > 0)
            {
                sessionKey = new byte[16];
                new Random().NextBytes(sessionKey);
                authenticateMessage.EncryptedRandomSessionKey = RC4.Encrypt(keyExchangeKey, sessionKey);
            }
            else
            {
                sessionKey = keyExchangeKey;
            }

            if (useGSSAPI)
            {
                SimpleProtectedNegotiationTokenResponse outputToken = new SimpleProtectedNegotiationTokenResponse();
                outputToken.ResponseToken = authenticateMessage.GetBytes();
                return outputToken.GetBytes();
            }
            else
            {
                return authenticateMessage.GetBytes();
            }
        }

        private static ChallengeMessage GetChallengeMessage(byte[] messageBytes)
        {
            if (AuthenticationMessageUtils.IsSignatureValid(messageBytes))
            {
                MessageTypeName messageType = AuthenticationMessageUtils.GetMessageType(messageBytes);
                if (messageType == MessageTypeName.Challenge)
                {
                    try
                    {
                        return new ChallengeMessage(messageBytes);
                    }
                    catch
                    {
                        return null;
                    }
                }
            }
            return null;
        }

        private static bool ContainsMechanism(SimpleProtectedNegotiationTokenInit token, byte[] mechanismIdentifier)
        {
            for (int index = 0; index < token.MechanismTypeList.Count; index++)
            {
                if (ByteUtils.AreByteArraysEqual(token.MechanismTypeList[index], GSSProvider.NTLMSSPIdentifier))
                {
                    return true;
                }
            }
            return false;
        }
    }
}