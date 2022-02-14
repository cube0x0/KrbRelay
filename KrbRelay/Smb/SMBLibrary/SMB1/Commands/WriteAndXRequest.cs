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
    /// SMB_COM_WRITE_ANDX Request
    /// SMB 1.0: The 2 reserved bytes at offset 18 become DataLengthHigh (used when the CAP_LARGE_WRITEX capability has been negotiated)
    /// </summary>
    public class WriteAndXRequest : SMBAndXCommand
    {
        public const int ParametersFixedLength = 24;

        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public ushort FID;

        public ulong Offset; // 4 bytes + 4 optional 'OffsetHigh' bytes
        public uint Timeout;
        public WriteMode WriteMode;
        public ushort Remaining;

        //uint DataLength; // 2 bytes + 2 'DataLengthHigh' bytes
        //ushort DataOffset;
        // ulong OffsetHigh; // Optional
        // Data:
        // Optional 1 byte padding
        public byte[] Data;

        public WriteAndXRequest() : base()
        { }

        public WriteAndXRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            Offset = LittleEndianConverter.ToUInt32(this.SMBParameters, 6);
            Timeout = LittleEndianConverter.ToUInt32(this.SMBParameters, 10);
            WriteMode = (WriteMode)LittleEndianConverter.ToUInt16(this.SMBParameters, 14);
            Remaining = LittleEndianConverter.ToUInt16(this.SMBParameters, 16);
            ushort dataLengthHigh = LittleEndianConverter.ToUInt16(this.SMBParameters, 18);
            uint DataLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 20);
            ushort DataOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 22);
            if (SMBParameters.Length == ParametersFixedLength + 4)
            {
                uint offsetHigh = LittleEndianConverter.ToUInt32(this.SMBParameters, 24);
                Offset |= ((ulong)offsetHigh << 32);
            }

            DataLength |= (uint)(dataLengthHigh << 16);

            Data = ByteReader.ReadBytes(buffer, (int)DataOffset, (int)DataLength);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            uint DataLength = (uint)Data.Length;
            // WordCount + ByteCount are additional 3 bytes
            ushort DataOffset = SMB1Header.Length + 3 + ParametersFixedLength;
            if (isUnicode)
            {
                DataOffset++;
            }
            ushort dataLengthHigh = (ushort)(DataLength >> 16);

            int parametersLength = ParametersFixedLength;
            if (Offset > UInt32.MaxValue)
            {
                parametersLength += 4;
                DataOffset += 4;
            }

            this.SMBParameters = new byte[parametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, FID);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 6, (uint)(Offset & 0xFFFFFFFF));
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 10, Timeout);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, (ushort)WriteMode);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 16, Remaining);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 18, dataLengthHigh);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 20, (ushort)(DataLength & 0xFFFF));
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 22, DataOffset);
            if (Offset > UInt32.MaxValue)
            {
                uint offsetHigh = (uint)(Offset >> 32);
                LittleEndianWriter.WriteUInt32(this.SMBParameters, 24, offsetHigh);
            }

            int smbDataLength = Data.Length;
            if (isUnicode)
            {
                smbDataLength++;
            }
            this.SMBData = new byte[smbDataLength];
            int offset = 0;
            if (isUnicode)
            {
                offset++;
            }
            ByteWriter.WriteBytes(this.SMBData, ref offset, this.Data);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_WRITE_ANDX;
            }
        }
    }
}