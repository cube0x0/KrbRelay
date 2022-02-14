/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_TRANSACTION2 Response
    /// The SMB_COM_TRANSACTION2 response format is identical to that of the SMB_COM_TRANSACTION response.
    /// </summary>
    public class Transaction2Response : TransactionResponse
    {
        public Transaction2Response() : base()
        {
        }

        public Transaction2Response(byte[] buffer, int offset) : base(buffer, offset)
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