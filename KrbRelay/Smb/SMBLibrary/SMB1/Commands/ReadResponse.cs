/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_READ Response
    /// </summary>
    public class ReadResponse : SMB1Command
    {
        public const int ParametersLength = 10;
        public const int SupportedBufferFormat = 0x01;

        // Parameters:
        public ushort CountOfBytesReturned;

        public byte[] Reserved; // 8 reserved bytes

        // Data:
        public byte BufferFormat;

        // ushort CountOfBytesRead;
        public byte[] Bytes;

        public ReadResponse() : base()
        {
            Reserved = new byte[8];
        }

        public ReadResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            CountOfBytesReturned = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            Reserved = ByteReader.ReadBytes(this.SMBParameters, 2, 8);

            BufferFormat = ByteReader.ReadByte(this.SMBData, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            ushort CountOfBytesRead = LittleEndianConverter.ToUInt16(this.SMBData, 1);
            Bytes = ByteReader.ReadBytes(this.SMBData, 3, CountOfBytesRead);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, CountOfBytesReturned);
            ByteWriter.WriteBytes(this.SMBParameters, 2, Reserved, 8);

            this.SMBData = new byte[3 + Bytes.Length];
            ByteWriter.WriteByte(this.SMBData, 0, BufferFormat);
            LittleEndianWriter.WriteUInt16(this.SMBData, 1, (ushort)Bytes.Length);
            ByteWriter.WriteBytes(this.SMBData, 3, Bytes);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_READ;
            }
        }
    }
}