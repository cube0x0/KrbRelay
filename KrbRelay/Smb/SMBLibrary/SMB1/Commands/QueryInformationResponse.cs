/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// SMB_COM_QUERY_INFORMATION Response.
    /// This command is deprecated.
    /// This command is used by Windows NT4 SP6.
    /// </summary>
    public class QueryInformationResponse : SMB1Command
    {
        public const int ParameterLength = 20;

        // Parameters:
        public SMBFileAttributes FileAttributes;

        public DateTime? LastWriteTime;
        public uint FileSize;
        public byte[] Reserved; // 10 bytes

        public QueryInformationResponse() : base()
        {
            Reserved = new byte[10];
        }

        public QueryInformationResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            LastWriteTime = UTimeHelper.ReadNullableUTime(this.SMBParameters, 2);
            FileSize = LittleEndianConverter.ToUInt32(this.SMBParameters, 6);
            Reserved = ByteReader.ReadBytes(this.SMBParameters, 10, 10);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParameterLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(this.SMBParameters, 2, LastWriteTime);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 6, FileSize);
            ByteWriter.WriteBytes(this.SMBParameters, 10, Reserved, 10);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_QUERY_INFORMATION;
            }
        }
    }
}