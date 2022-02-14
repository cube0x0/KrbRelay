/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_SET_NMPIPE_STATE Response
    /// </summary>
    public class TransactionSetNamedPipeStateResponse : TransactionSubcommand
    {
        public const int ParametersLength = 0;

        public override TransactionSubcommandName SubcommandName
        {
            get
            {
                return TransactionSubcommandName.TRANS_SET_NMPIPE_STATE;
            }
        }
    }
}