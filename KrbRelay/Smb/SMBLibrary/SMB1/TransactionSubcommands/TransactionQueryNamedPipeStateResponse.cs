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
    /// TRANS_QUERY_NMPIPE_STATE Response
    /// </summary>
    public class TransactionQueryNamedPipeStateResponse : TransactionSubcommand
    {
        public const int ParametersLength = 2;

        // Parameters;
        public NamedPipeStatus NMPipeStatus;

        public TransactionQueryNamedPipeStateResponse() : base()
        {
        }

        public TransactionQueryNamedPipeStateResponse(byte[] parameters) : base()
        {
            NMPipeStatus = new NamedPipeStatus(LittleEndianConverter.ToUInt16(parameters, 0));
        }

        public override byte[] GetSetup()
        {
            return new byte[0];
        }

        public override byte[] GetParameters()
        {
            byte[] parameters = new byte[2];
            NMPipeStatus.WriteBytes(parameters, 0);
            return parameters;
        }

        public override TransactionSubcommandName SubcommandName
        {
            get
            {
                return TransactionSubcommandName.TRANS_QUERY_NMPIPE_STATE;
            }
        }
    }
}