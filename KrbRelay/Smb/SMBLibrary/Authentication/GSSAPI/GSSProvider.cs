/* Copyright (C) 2017-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.NTLM;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.Authentication.GSSAPI
{
    public class GSSContext
    {
        internal IGSSMechanism Mechanism;
        internal object MechanismContext;

        internal GSSContext(IGSSMechanism mechanism, object mechanismContext)
        {
            Mechanism = mechanism;
            MechanismContext = mechanismContext;
        }
    }

    public class GSSProvider
    {
        public static readonly byte[] NTLMSSPIdentifier = new byte[] { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

        private List<IGSSMechanism> m_mechanisms;

        public GSSProvider(IGSSMechanism mechanism)
        {
            m_mechanisms = new List<IGSSMechanism>();
            m_mechanisms.Add(mechanism);
        }

        public GSSProvider(List<IGSSMechanism> mechanisms)
        {
            m_mechanisms = mechanisms;
        }

        public byte[] GetSPNEGOTokenInitBytes()
        {
            SimpleProtectedNegotiationTokenInit token = new SimpleProtectedNegotiationTokenInit();
            token.MechanismTypeList = new List<byte[]>();
            foreach (IGSSMechanism mechanism in m_mechanisms)
            {
                token.MechanismTypeList.Add(mechanism.Identifier);
            }
            return token.GetBytes(true);
        }

        public virtual NTStatus AcceptSecurityContext(ref GSSContext context, byte[] inputToken, out byte[] outputToken)
        {
            outputToken = null;
            SimpleProtectedNegotiationToken spnegoToken = null;
            try
            {
                spnegoToken = SimpleProtectedNegotiationToken.ReadToken(inputToken, 0, false);
            }
            catch
            {
            }

            if (spnegoToken != null)
            {
                if (spnegoToken is SimpleProtectedNegotiationTokenInit)
                {
                    SimpleProtectedNegotiationTokenInit tokenInit = (SimpleProtectedNegotiationTokenInit)spnegoToken;
                    if (tokenInit.MechanismTypeList.Count == 0)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }

                    // RFC 4178: Note that in order to avoid an extra round trip, the first context establishment token
                    // of the initiator's preferred mechanism SHOULD be embedded in the initial negotiation message.
                    byte[] preferredMechanism = tokenInit.MechanismTypeList[0];
                    IGSSMechanism mechanism = FindMechanism(preferredMechanism);
                    bool isPreferredMechanism = (mechanism != null);
                    if (!isPreferredMechanism)
                    {
                        mechanism = FindMechanism(tokenInit.MechanismTypeList);
                    }

                    if (mechanism != null)
                    {
                        NTStatus status;
                        context = new GSSContext(mechanism, null);
                        if (isPreferredMechanism)
                        {
                            byte[] mechanismOutput;
                            status = mechanism.AcceptSecurityContext(ref context.MechanismContext, tokenInit.MechanismToken, out mechanismOutput);
                            outputToken = GetSPNEGOTokenResponseBytes(mechanismOutput, status, mechanism.Identifier);
                        }
                        else
                        {
                            status = NTStatus.SEC_I_CONTINUE_NEEDED;
                            outputToken = GetSPNEGOTokenResponseBytes(null, status, mechanism.Identifier);
                        }
                        return status;
                    }
                    return NTStatus.SEC_E_SECPKG_NOT_FOUND;
                }
                else // SimpleProtectedNegotiationTokenResponse
                {
                    if (context == null)
                    {
                        return NTStatus.SEC_E_INVALID_TOKEN;
                    }
                    IGSSMechanism mechanism = context.Mechanism;
                    SimpleProtectedNegotiationTokenResponse tokenResponse = (SimpleProtectedNegotiationTokenResponse)spnegoToken;
                    byte[] mechanismOutput;
                    NTStatus status = mechanism.AcceptSecurityContext(ref context.MechanismContext, tokenResponse.ResponseToken, out mechanismOutput);
                    outputToken = GetSPNEGOTokenResponseBytes(mechanismOutput, status, null);
                    return status;
                }
            }
            else
            {
                // [MS-SMB] The Windows GSS implementation supports raw Kerberos / NTLM messages in the SecurityBlob.
                // [MS-SMB2] Windows [..] will also accept raw Kerberos messages and implicit NTLM messages as part of GSS authentication.
                if (AuthenticationMessageUtils.IsSignatureValid(inputToken))
                {
                    MessageTypeName messageType = AuthenticationMessageUtils.GetMessageType(inputToken);
                    IGSSMechanism ntlmAuthenticationProvider = FindMechanism(NTLMSSPIdentifier);
                    if (ntlmAuthenticationProvider != null)
                    {
                        if (messageType == MessageTypeName.Negotiate)
                        {
                            context = new GSSContext(ntlmAuthenticationProvider, null);
                        }

                        if (context == null)
                        {
                            return NTStatus.SEC_E_INVALID_TOKEN;
                        }

                        NTStatus status = ntlmAuthenticationProvider.AcceptSecurityContext(ref context.MechanismContext, inputToken, out outputToken);
                        return status;
                    }
                    else
                    {
                        return NTStatus.SEC_E_SECPKG_NOT_FOUND;
                    }
                }
            }
            return NTStatus.SEC_E_INVALID_TOKEN;
        }

        public virtual object GetContextAttribute(GSSContext context, GSSAttributeName attributeName)
        {
            if (context == null)
            {
                return null;
            }
            IGSSMechanism mechanism = context.Mechanism;
            return mechanism.GetContextAttribute(context.MechanismContext, attributeName);
        }

        public virtual bool DeleteSecurityContext(ref GSSContext context)
        {
            if (context != null)
            {
                IGSSMechanism mechanism = context.Mechanism;
                return mechanism.DeleteSecurityContext(ref context.MechanismContext);
            }
            return false;
        }

        /// <summary>
        /// Helper method for legacy implementation.
        /// </summary>
        public virtual NTStatus GetNTLMChallengeMessage(out GSSContext context, NegotiateMessage negotiateMessage, out ChallengeMessage challengeMessage)
        {
            IGSSMechanism ntlmAuthenticationProvider = FindMechanism(NTLMSSPIdentifier);
            if (ntlmAuthenticationProvider != null)
            {
                context = new GSSContext(ntlmAuthenticationProvider, null);
                byte[] outputToken;
                NTStatus result = ntlmAuthenticationProvider.AcceptSecurityContext(ref context.MechanismContext, negotiateMessage.GetBytes(), out outputToken);
                challengeMessage = new ChallengeMessage(outputToken);
                return result;
            }
            else
            {
                context = null;
                challengeMessage = null;
                return NTStatus.SEC_E_SECPKG_NOT_FOUND;
            }
        }

        /// <summary>
        /// Helper method for legacy implementation.
        /// </summary>
        public virtual NTStatus NTLMAuthenticate(GSSContext context, AuthenticateMessage authenticateMessage)
        {
            if (context != null && ByteUtils.AreByteArraysEqual(context.Mechanism.Identifier, NTLMSSPIdentifier))
            {
                IGSSMechanism mechanism = context.Mechanism;
                byte[] outputToken;
                NTStatus result = mechanism.AcceptSecurityContext(ref context.MechanismContext, authenticateMessage.GetBytes(), out outputToken);
                return result;
            }
            else
            {
                return NTStatus.SEC_E_SECPKG_NOT_FOUND;
            }
        }

        public IGSSMechanism FindMechanism(List<byte[]> mechanismIdentifiers)
        {
            foreach (byte[] identifier in mechanismIdentifiers)
            {
                IGSSMechanism mechanism = FindMechanism(identifier);
                if (mechanism != null)
                {
                    return mechanism;
                }
            }
            return null;
        }

        public IGSSMechanism FindMechanism(byte[] mechanismIdentifier)
        {
            foreach (IGSSMechanism mechanism in m_mechanisms)
            {
                if (ByteUtils.AreByteArraysEqual(mechanism.Identifier, mechanismIdentifier))
                {
                    return mechanism;
                }
            }
            return null;
        }

        private static byte[] GetSPNEGOTokenResponseBytes(byte[] mechanismOutput, NTStatus status, byte[] mechanismIdentifier)
        {
            SimpleProtectedNegotiationTokenResponse tokenResponse = new SimpleProtectedNegotiationTokenResponse();
            if (status == NTStatus.STATUS_SUCCESS)
            {
                tokenResponse.NegState = NegState.AcceptCompleted;
            }
            else if (status == NTStatus.SEC_I_CONTINUE_NEEDED)
            {
                tokenResponse.NegState = NegState.AcceptIncomplete;
            }
            else
            {
                tokenResponse.NegState = NegState.Reject;
            }
            tokenResponse.SupportedMechanism = mechanismIdentifier;
            tokenResponse.ResponseToken = mechanismOutput;
            return tokenResponse.GetBytes();
        }
    }
}