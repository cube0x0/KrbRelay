/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.GSSAPI;

namespace SMBLibrary.Authentication.NTLM
{
    public abstract class NTLMAuthenticationProviderBase : IGSSMechanism
    {
        public static readonly byte[] NTLMSSPIdentifier = new byte[] { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };

        public NTStatus AcceptSecurityContext(ref object context, byte[] inputToken, out byte[] outputToken)
        {
            outputToken = null;
            if (!AuthenticationMessageUtils.IsSignatureValid(inputToken))
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }

            MessageTypeName messageType = AuthenticationMessageUtils.GetMessageType(inputToken);
            if (messageType == MessageTypeName.Negotiate)
            {
                NTStatus status = GetChallengeMessage(out context, inputToken, out outputToken);
                return status;
            }
            else if (messageType == MessageTypeName.Authenticate)
            {
                return Authenticate(context, inputToken);
            }
            else
            {
                return NTStatus.SEC_E_INVALID_TOKEN;
            }
        }

        public abstract NTStatus GetChallengeMessage(out object context, byte[] negotiateMessageBytes, out byte[] challengeMessageBytes);

        public abstract NTStatus Authenticate(object context, byte[] authenticateMessageBytes);

        public abstract bool DeleteSecurityContext(ref object context);

        public abstract object GetContextAttribute(object context, GSSAttributeName attributeName);

        public byte[] Identifier
        {
            get
            {
                return NTLMSSPIdentifier;
            }
        }
    }
}