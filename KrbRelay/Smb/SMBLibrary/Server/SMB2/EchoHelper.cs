/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;

namespace SMBLibrary.Server.SMB2
{
    internal class EchoHelper
    {
        internal static EchoResponse GetUnsolicitedEchoResponse()
        {
            // [MS-SMB2] 3.2.5.1.2 - If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request, and the client MUST NOT attempt to locate the request, but instead process it as follows:
            // If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19. Otherwise, the response MUST be discarded as invalid.
            EchoResponse response = new EchoResponse();
            response.Header.MessageID = 0xFFFFFFFFFFFFFFFF;
            return response;
        }
    }
}