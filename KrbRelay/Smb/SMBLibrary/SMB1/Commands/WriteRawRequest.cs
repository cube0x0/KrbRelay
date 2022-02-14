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
    /// SMB_COM_WRITE_RAW Request
    /// </summary>
    public class WriteRawRequest : SMB1Command
    {
        public const int ParametersFixedLength = 24; // + 4 optional bytes

        // Parameters:
        public ushort FID;

        public ushort CountOfBytes;
        public ushort Reserved1;
        public uint Offset;
        public uint Timeout;
        public WriteMode WriteMode;
        public uint Reserved2;

        //ushort DataLength;
        //ushort DataOffset;
        public uint OffsetHigh; // Optional

        // Data:
        public byte[] Data;

        public WriteRawRequest() : base()
        {
            Data = new byte[0];
        }

        public WriteRawRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            CountOfBytes = LittleEndianConverter.ToUInt16(this.SMBParameters, 2);
            Reserved1 = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            Offset = LittleEndianConverter.ToUInt32(this.SMBParameters, 6);
            Timeout = LittleEndianConverter.ToUInt32(this.SMBParameters, 10);
            WriteMode = (WriteMode)LittleEndianConverter.ToUInt16(this.SMBParameters, 14);
            Reserved2 = LittleEndianConverter.ToUInt32(this.SMBParameters, 16);
            ushort dataLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 20);
            ushort dataOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 22);
            if (SMBParameters.Length == ParametersFixedLength + 4)
            {
                OffsetHigh = LittleEndianConverter.ToUInt32(this.SMBParameters, 24);
            }

            Data = ByteReader.ReadBytes(buffer, dataOffset, dataLength);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            throw new NotImplementedException();
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_WRITE_RAW;
            }
        }
    }
}