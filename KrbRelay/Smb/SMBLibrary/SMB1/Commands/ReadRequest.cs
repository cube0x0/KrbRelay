/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_READ Request
    /// </summary>
    public class ReadRequest : SMB1Command
    {
        public const int ParametersLength = 10;

        // Parameters:
        public ushort FID;

        public ushort CountOfBytesToRead;
        public uint ReadOffsetInBytes;
        public ushort EstimateOfRemainingBytesToBeRead;

        public ReadRequest() : base()
        {
        }

        public ReadRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            CountOfBytesToRead = LittleEndianConverter.ToUInt16(this.SMBParameters, 2);
            ReadOffsetInBytes = LittleEndianConverter.ToUInt32(this.SMBParameters, 4);
            CountOfBytesToRead = LittleEndianConverter.ToUInt16(this.SMBParameters, 8);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, FID);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 2, CountOfBytesToRead);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 4, ReadOffsetInBytes);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, CountOfBytesToRead);
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