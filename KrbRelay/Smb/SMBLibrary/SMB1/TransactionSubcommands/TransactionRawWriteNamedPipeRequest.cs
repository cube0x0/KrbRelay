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
    /// TRANS_RAW_WRITE_NMPIPE Request
    /// </summary>
    public class TransactionRawWriteNamedPipeRequest : TransactionSubcommand
    {
        // Setup:
        public ushort FID;

        // Data:
        public byte[] WriteData;

        public TransactionRawWriteNamedPipeRequest() : base()
        {
        }

        public TransactionRawWriteNamedPipeRequest(byte[] setup, byte[] data) : base()
        {
            FID = LittleEndianConverter.ToUInt16(setup, 2);

            WriteData = data;
        }

        public override byte[] GetSetup()
        {
            byte[] setup = new byte[4];
            LittleEndianWriter.WriteUInt16(setup, 0, (ushort)this.SubcommandName);
            LittleEndianWriter.WriteUInt16(setup, 2, FID);
            return setup;
        }

        public override byte[] GetData(bool isUnicode)
        {
            return WriteData;
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