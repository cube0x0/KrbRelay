/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_NT_TRANSACT Interim Response
    /// </summary>
    public class NTTransactInterimResponse : SMB1Command
    {
        public const int ParametersLength = 0;

        public NTTransactInterimResponse() : base()
        {
        }

        public NTTransactInterimResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_NT_TRANSACT;
            }
        }
    }
}