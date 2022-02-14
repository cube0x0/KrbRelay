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
    /// SMB_COM_SET_INFORMATION Request
    /// </summary>
    public class SetInformationRequest : SMB1Command
    {
        public const int ParametersLength = 16;
        public const int SupportedBufferFormat = 0x04;

        // Parameters:
        public SMBFileAttributes FileAttributes;

        public DateTime? LastWriteTime;
        public byte[] Reserved; // 10 bytes

        // Data:
        public byte BufferFormat;

        public string FileName; // SMB_STRING

        public SetInformationRequest() : base()
        {
            Reserved = new byte[10];
            BufferFormat = SupportedBufferFormat;
        }

        public SetInformationRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            LastWriteTime = UTimeHelper.ReadNullableUTime(this.SMBParameters, 2);
            Reserved = ByteReader.ReadBytes(this.SMBParameters, 6, 10);

            BufferFormat = ByteReader.ReadByte(this.SMBData, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            FileName = SMB1Helper.ReadSMBString(this.SMBData, 1, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(this.SMBParameters, 2, LastWriteTime);
            ByteWriter.WriteBytes(this.SMBParameters, 6, Reserved, 10);

            int length = 1;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }
            this.SMBData = new byte[length];
            ByteWriter.WriteByte(this.SMBData, 0, BufferFormat);
            SMB1Helper.WriteSMBString(this.SMBData, 1, isUnicode, FileName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_SET_INFORMATION;
            }
        }
    }
}