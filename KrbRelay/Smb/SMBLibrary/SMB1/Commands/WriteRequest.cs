/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_WRITE Request.
    /// This command is obsolete.
    /// Windows NT4 SP6 will send this command with empty data for some reason.
    /// </summary>
    public class WriteRequest : SMB1Command
    {
        public const int ParametersLength = 8;
        public const int SupportedBufferFormat = 0x01;

        // Parameters:
        public ushort FID;

        public ushort CountOfBytesToWrite;
        public ushort WriteOffsetInBytes;
        public ushort EstimateOfRemainingBytesToBeWritten;

        // Data:
        public byte BufferFormat;

        // ushort DataLength;
        public byte[] Data;

        public WriteRequest() : base()
        {
            BufferFormat = SupportedBufferFormat;
            Data = new byte[0];
        }

        public WriteRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            CountOfBytesToWrite = LittleEndianConverter.ToUInt16(this.SMBParameters, 2);
            WriteOffsetInBytes = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            EstimateOfRemainingBytesToBeWritten = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);

            BufferFormat = ByteReader.ReadByte(this.SMBData, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            ushort dataLength = LittleEndianConverter.ToUInt16(this.SMBData, 1);
            Data = ByteReader.ReadBytes(this.SMBData, 3, dataLength);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            if (Data.Length > UInt16.MaxValue)
            {
                throw new ArgumentException("Invalid Data length");
            }
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, FID);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 2, CountOfBytesToWrite);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, WriteOffsetInBytes);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, EstimateOfRemainingBytesToBeWritten);

            this.SMBData = new byte[3 + Data.Length];
            ByteWriter.WriteByte(this.SMBData, 0, BufferFormat);
            LittleEndianWriter.WriteUInt16(this.SMBData, 1, (ushort)Data.Length);
            ByteWriter.WriteBytes(this.SMBData, 3, Data);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_WRITE;
            }
        }
    }
}