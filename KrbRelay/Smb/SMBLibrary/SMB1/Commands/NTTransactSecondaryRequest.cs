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
    /// SMB_COM_NT_TRANSACT_SECONDARY Request
    /// </summary>
    public class NTTransactSecondaryRequest : SMB1Command
    {
        public const int SMBParametersLength = 36;

        // Parameters:
        public byte[] Reserved1; // 3 bytes

        public uint TotalParameterCount;
        public uint TotalDataCount;

        //uint ParameterCount;
        //uint ParameterOffset;
        public uint ParameterDisplacement;

        //uint DataCount;
        //uint DataOffset;
        public uint DataDisplacement;

        public byte Reserved2;

        // Data:
        // Padding (alignment to 4 byte boundary)
        public byte[] TransParameters; // Trans_Parameters

        // Padding (alignment to 4 byte boundary)
        public byte[] TransData; // Trans_Data

        public NTTransactSecondaryRequest() : base()
        {
            Reserved1 = new byte[3];
        }

        public NTTransactSecondaryRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            int readOffset = 0;
            Reserved1 = ByteReader.ReadBytes(this.SMBParameters, ref readOffset, 3);
            TotalParameterCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            TotalDataCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint parameterCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint parameterOffset = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            ParameterDisplacement = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint dataCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint dataOffset = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            DataDisplacement = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            Reserved2 = ByteReader.ReadByte(this.SMBParameters, ref readOffset);

            TransParameters = ByteReader.ReadBytes(buffer, (int)parameterOffset, (int)parameterCount);
            TransData = ByteReader.ReadBytes(buffer, (int)dataOffset, (int)dataCount);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            uint parameterCount = (ushort)TransParameters.Length;
            uint dataCount = (ushort)TransData.Length;

            // WordCount + ByteCount are additional 3 bytes
            uint parameterOffset = (ushort)(SMB1Header.Length + 3 + (SMBParametersLength));
            int padding1 = (int)(4 - (parameterOffset % 4)) % 4;
            parameterOffset += (ushort)padding1;
            uint dataOffset = (ushort)(parameterOffset + parameterCount);
            int padding2 = (int)(4 - (dataOffset % 4)) % 4;
            dataOffset += (ushort)padding2;

            this.SMBParameters = new byte[SMBParametersLength];
            int writeOffset = 0;
            ByteWriter.WriteBytes(this.SMBParameters, ref writeOffset, Reserved1, 3);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, TotalParameterCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, TotalDataCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, parameterCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, parameterOffset);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, ParameterDisplacement);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, dataCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, dataOffset);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, DataDisplacement);
            ByteWriter.WriteByte(this.SMBParameters, ref writeOffset, Reserved2);

            this.SMBData = new byte[parameterCount + dataCount + padding1 + padding2];
            ByteWriter.WriteBytes(this.SMBData, padding1, TransParameters);
            ByteWriter.WriteBytes(this.SMBData, (int)(padding1 + parameterCount + padding2), TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_NT_TRANSACT_SECONDARY;
            }
        }
    }
}