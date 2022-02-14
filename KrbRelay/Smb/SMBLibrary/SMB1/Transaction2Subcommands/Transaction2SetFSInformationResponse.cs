/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_SET_FS_INFORMATION Response
    /// </summary>
    public class Transaction2SetFSInformationResponse : Transaction2Subcommand
    {
        public const int ParametersLength = 0;

        public Transaction2SetFSInformationResponse() : base()
        {
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_SET_FS_INFORMATION;
            }
        }
    }
}