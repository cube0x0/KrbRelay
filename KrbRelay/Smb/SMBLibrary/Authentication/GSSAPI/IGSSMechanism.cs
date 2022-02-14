/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.Authentication.GSSAPI
{
    public interface IGSSMechanism
    {
        /// <summary>
        /// Equivalent to GSS_Accept_sec_context
        /// </summary>
        NTStatus AcceptSecurityContext(ref object context, byte[] inputToken, out byte[] outputToken);

        /// <summary>
        /// Equivalent to GSS_Delete_sec_context
        /// </summary>
        bool DeleteSecurityContext(ref object context);

        /// <summary>
        /// Equivalent to GSS_Inquire_context
        /// Obtains information about a given security context (even an incomplete one)
        /// </summary>
        object GetContextAttribute(object context, GSSAttributeName attributeName);

        byte[] Identifier
        {
            get;
        }
    }
}