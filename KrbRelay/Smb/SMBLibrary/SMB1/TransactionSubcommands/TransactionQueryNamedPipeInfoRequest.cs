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
    /// TRANS_QUERY_NMPIPE_INFO Request
    /// </summary>
    public class TransactionQueryNamedPipeInfoRequest : TransactionSubcommand
    {
        // Setup:
        public ushort FID;

        // Parameters:
        public ushort Level; // Must be 0x0001

        public TransactionQueryNamedPipeInfoRequest() : base()
        {
        }

        public TransactionQueryNamedPipeInfoRequest(byte[] setup, byte[] parameters) : base()
        {
            FID = LittleEndianConverter.ToUInt16(setup, 2);

            Level = LittleEndianConverter.ToUInt16(parameters, 0);
        }

        public override byte[] GetSetup()
        {
            byte[] setup = new byte[4];
            LittleEndianWriter.WriteUInt16(setup, 0, (ushort)this.SubcommandName);
            LittleEndianWriter.WriteUInt16(setup, 2, FID);
            return setup;
        }

        public override byte[] GetParameters()
        {
            return LittleEndianConverter.GetBytes(Level);
        }

        public override TransactionSubcommandName SubcommandName
        {
            get
            {
                return TransactionSubcommandName.TRANS_QUERY_NMPIPE_INFO;
            }
        }
    }
}