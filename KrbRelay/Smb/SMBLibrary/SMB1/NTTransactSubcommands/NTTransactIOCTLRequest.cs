/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// NT_TRANSACT_IOCTL Request
    /// </summary>
    public class NTTransactIOCTLRequest : NTTransactSubcommand
    {
        public const int SetupLength = 8;

        // Setup:
        public uint FunctionCode;

        public ushort FID;
        public bool IsFsctl;
        public bool IsFlags;

        // Data:
        public byte[] Data;

        public NTTransactIOCTLRequest() : base()
        {
            Data = new byte[0];
        }

        public NTTransactIOCTLRequest(byte[] setup, byte[] data) : base()
        {
            FunctionCode = LittleEndianConverter.ToUInt32(setup, 0);
            FID = LittleEndianConverter.ToUInt16(setup, 4);
            IsFsctl = (ByteReader.ReadByte(setup, 6) != 0);
            IsFlags = (ByteReader.ReadByte(setup, 7) != 0);

            Data = data;
        }

        public override byte[] GetSetup()
        {
            byte[] setup = new byte[SetupLength];
            LittleEndianWriter.WriteUInt32(setup, 0, FunctionCode);
            LittleEndianWriter.WriteUInt32(setup, 4, FID);
            ByteWriter.WriteByte(setup, 6, Convert.ToByte(IsFsctl));
            ByteWriter.WriteByte(setup, 7, Convert.ToByte(IsFlags));
            return setup;
        }

        public override byte[] GetData()
        {
            return Data;
        }

        public override NTTransactSubcommandName SubcommandName
        {
            get
            {
                return NTTransactSubcommandName.NT_TRANSACT_IOCTL;
            }
        }
    }
}