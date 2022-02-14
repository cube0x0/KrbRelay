/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// TRANS_RAW_WRITE_NMPIPE Response
    /// </summary>
    public class TransactionRawWriteNamedPipeResponse : TransactionSubcommand
    {
        public const int ParametersLength = 2;

        // Parameters;
        public ushort BytesWritten;

        public TransactionRawWriteNamedPipeResponse() : base()
        {
        }

        public TransactionRawWriteNamedPipeResponse(byte[] parameters) : base()
        {
            BytesWritten = LittleEndianConverter.ToUInt16(parameters, 0);
        }

        public override byte[] GetParameters()
        {
            return LittleEndianConverter.GetBytes(BytesWritten);
        }

        public override TransactionSubcommandName SubcommandName
        {
            get
            {
                return TransactionSubcommandName.TRANS_RAW_WRITE_NMPIPE;
            }
        }
    }
}