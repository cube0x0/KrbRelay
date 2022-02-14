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
    /// SMB_COM_DELETE_DIRECTORY Request
    /// </summary>
    public class DeleteDirectoryRequest : SMB1Command
    {
        public const int SupportedBufferFormat = 0x04;

        // Data:
        public byte BufferFormat;

        public string DirectoryName; // SMB_STRING

        public DeleteDirectoryRequest() : base()
        {
            BufferFormat = SupportedBufferFormat;
        }

        public DeleteDirectoryRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            BufferFormat = ByteReader.ReadByte(this.SMBData, 0);
            if (BufferFormat != SupportedBufferFormat)
            {
                throw new InvalidDataException("Unsupported Buffer Format");
            }
            DirectoryName = SMB1Helper.ReadSMBString(this.SMBData, 1, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            int length = 1;
            if (isUnicode)
            {
                length += DirectoryName.Length * 2 + 2;
            }
            else
            {
                length += DirectoryName.Length + 1;
            }
            this.SMBData = new byte[length];
            ByteWriter.WriteByte(this.SMBData, 0, BufferFormat);
            SMB1Helper.WriteSMBString(this.SMBData, 1, isUnicode, DirectoryName);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_DELETE_DIRECTORY;
            }
        }
    }
}