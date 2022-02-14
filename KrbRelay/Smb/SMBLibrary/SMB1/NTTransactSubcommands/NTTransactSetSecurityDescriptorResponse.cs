/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// NT_TRANSACT_SET_SECURITY_DESC Response
    /// </summary>
    public class NTTransactSetSecurityDescriptorResponse : NTTransactSubcommand
    {
        public const int ParametersLength = 0;

        public NTTransactSetSecurityDescriptorResponse()
        {
        }

        public override NTTransactSubcommandName SubcommandName
        {
            get
            {
                return NTTransactSubcommandName.NT_TRANSACT_SET_SECURITY_DESC;
            }
        }
    }
}