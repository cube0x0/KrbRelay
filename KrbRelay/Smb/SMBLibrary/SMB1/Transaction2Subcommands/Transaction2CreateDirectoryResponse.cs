/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS2_CREATE_DIRECTORY Response
    /// </summary>
    public class Transaction2CreateDirectoryResponse : Transaction2Subcommand
    {
        public const int ParametersLength = 2;

        // Parameters:
        public ushort EaErrorOffset;

        public Transaction2CreateDirectoryResponse() : base()
        {
        }

        public Transaction2CreateDirectoryResponse(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            EaErrorOffset = LittleEndianConverter.ToUInt16(parameters, 0);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            byte[] parameters = new byte[2];
            LittleEndianWriter.WriteUInt16(parameters, 0, EaErrorOffset);
            return parameters;
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_CREATE_DIRECTORY;
            }
        }
    }
}