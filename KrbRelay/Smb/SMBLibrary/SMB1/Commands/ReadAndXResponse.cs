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
    /// SMB_COM_READ_ANDX Response
    /// SMB 1.0: The 2 reserved bytes at offset 14 become DataLengthHigh (used when the CAP_LARGE_READX capability has been negotiated)
    /// </summary>
    public class ReadAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 24;

        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public ushort Available;

        public ushort DataCompactionMode; // Not used and MUST be 0x0000
        public ushort Reserved1;

        //uint DataLength; // 2 bytes + 2 'DataLengthHigh' bytes
        //ushort DataOffset;
        public byte[] Reserved2; // 8 bytes

        // Data:
        // 1 byte padding - if unicode strings are being used, this field MUST be present, otherwise it's optional.
        public byte[] Data;

        public ReadAndXResponse() : base()
        {
            Reserved2 = new byte[8];
        }

        public ReadAndXResponse(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            Available = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            DataCompactionMode = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);
            Reserved1 = LittleEndianConverter.ToUInt16(this.SMBParameters, 8);
            uint DataLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 10);
            ushort DataOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 12);
            ushort dataLengthHigh = LittleEndianConverter.ToUInt16(this.SMBParameters, 14);
            Reserved2 = ByteReader.ReadBytes(buffer, 16, 8);

            DataLength |= (uint)(dataLengthHigh << 16);

            Data = ByteReader.ReadBytes(buffer, DataOffset, (int)DataLength);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            uint DataLength = (uint)Data.Length;
            // WordCount + ByteCount are additional 3 bytes
            ushort DataOffset = SMB1Header.Length + 3 + ParametersLength;
            if (isUnicode)
            {
                DataOffset++;
            }
            ushort dataLengthHigh = (ushort)(DataLength >> 16);

            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, Available);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, DataCompactionMode);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, Reserved1);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 10, (ushort)(DataLength & 0xFFFF));
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 12, DataOffset);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, dataLengthHigh);
            ByteWriter.WriteBytes(this.SMBParameters, 16, Reserved2);

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
            ByteWriter.WriteBytes(this.SMBData, offset, this.Data);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_READ_ANDX;
            }
        }
    }
}