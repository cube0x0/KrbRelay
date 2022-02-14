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
    /// SMB_COM_RENAME Request
    /// </summary>
    public class RenameRequest : SMB1Command
    {
        public const int SupportedBufferFormat = 0x04;
        public const int ParametersLength = 2;

        // Parameters:
        public SMBFileAttributes SearchAttributes;

        // Data:
        public byte BufferFormat1;

        public string OldFileName; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public byte BufferFormat2;
        public string NewFileName; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public RenameRequest() : base()
        {
            BufferFormat1 = SupportedBufferFormat;
            BufferFormat2 = SupportedBufferFormat;
        }

        public RenameRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            SearchAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(this.SMBParameters, 0);

            int dataOffset = 0;
            BufferFormat1 = ByteReader.ReadByte(this.SMBData, ref dataOffset);
            if (BufferFormat1 != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            OldFileName = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            BufferFormat2 = ByteReader.ReadByte(this.SMBData, ref dataOffset);
            if (BufferFormat2 != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            if (isUnicode)
            {
                dataOffset++;
            }
            NewFileName = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, (ushort)SearchAttributes);

            if (isUnicode)
            {
                int padding = 1;
                this.SMBData = new byte[2 + OldFileName.Length * 2 + NewFileName.Length * 2 + 4 + padding];
            }
            else
            {
                this.SMBData = new byte[2 + OldFileName.Length + NewFileName.Length + 2];
            }
            int dataOffset = 0;
            ByteWriter.WriteByte(this.SMBData, ref dataOffset, BufferFormat1);
            SMB1Helper.WriteSMBString(this.SMBData, ref dataOffset, isUnicode, OldFileName);
            ByteWriter.WriteByte(this.SMBData, ref dataOffset, BufferFormat2);
            if (isUnicode)
            {
                dataOffset++; // padding
            }
            SMB1Helper.WriteSMBString(this.SMBData, ref dataOffset, isUnicode, NewFileName);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_RENAME;
            }
        }
    }
}