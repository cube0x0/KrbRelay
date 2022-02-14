/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_TRANSACTION2 Request
    /// The SMB_COM_TRANSACTION2 request format is similar to that of the SMB_COM_TRANSACTION request except for the Name field.
    /// The differences are in the subcommands supported, and in the purposes and usages of some of the fields.
    /// </summary>
    public class Transaction2Request : TransactionRequest
    {
        public Transaction2Request() : base()
        {
        }

        public Transaction2Request(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_TRANSACTION2;
            }
        }
    }
}