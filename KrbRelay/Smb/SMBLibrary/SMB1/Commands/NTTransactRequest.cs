/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_NT_TRANSACT Request
    /// </summary>
    public class NTTransactRequest : SMB1Command
    {
        public const int FixedSMBParametersLength = 38;

        // Parameters:
        public byte MaxSetupCount;

        public ushort Reserved1;
        public uint TotalParameterCount;
        public uint TotalDataCount;
        public uint MaxParameterCount;
        public uint MaxDataCount;

        //uint ParameterCount;
        //uint ParameterOffset;
        //uint DataCount;
        //uint DataOffset;
        //byte SetupCount; // In 2-byte words
        public NTTransactSubcommandName Function;

        public byte[] Setup;

        // Data:
        // Padding (alignment to 4 byte boundary)
        public byte[] TransParameters; // Trans_Parameters

        // Padding (alignment to 4 byte boundary)
        public byte[] TransData; // Trans_Data

        public NTTransactRequest() : base()
        {
        }

        public NTTransactRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            int readOffset = 0;
            MaxSetupCount = ByteReader.ReadByte(this.SMBParameters, ref readOffset);
            Reserved1 = LittleEndianReader.ReadUInt16(this.SMBParameters, ref readOffset);
            TotalParameterCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            TotalDataCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            MaxParameterCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            MaxDataCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint parameterCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint parameterOffset = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint dataCount = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            uint dataOffset = LittleEndianReader.ReadUInt32(this.SMBParameters, ref readOffset);
            byte setupCount = ByteReader.ReadByte(this.SMBParameters, ref readOffset);
            Function = (NTTransactSubcommandName)LittleEndianReader.ReadUInt16(this.SMBParameters, ref readOffset);
            Setup = ByteReader.ReadBytes(this.SMBParameters, ref readOffset, setupCount * 2);

            TransParameters = ByteReader.ReadBytes(buffer, (int)parameterOffset, (int)parameterCount);
            TransData = ByteReader.ReadBytes(buffer, (int)dataOffset, (int)dataCount);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            byte setupCount = (byte)(Setup.Length / 2);
            uint parameterCount = (ushort)TransParameters.Length;
            uint dataCount = (ushort)TransData.Length;

            // WordCount + ByteCount are additional 3 bytes
            uint parameterOffset = (ushort)(SMB1Header.Length + 3 + (FixedSMBParametersLength + Setup.Length));
            int padding1 = (int)(4 - (parameterOffset % 4)) % 4;
            parameterOffset += (ushort)padding1;
            uint dataOffset = (ushort)(parameterOffset + parameterCount);
            int padding2 = (int)(4 - (dataOffset % 4)) % 4;
            dataOffset += (ushort)padding2;

            this.SMBParameters = new byte[FixedSMBParametersLength + Setup.Length];
            int writeOffset = 0;
            ByteWriter.WriteByte(this.SMBParameters, ref writeOffset, MaxSetupCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref writeOffset, Reserved1);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, TotalParameterCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, TotalDataCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, MaxParameterCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, MaxDataCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, parameterCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, parameterOffset);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, dataCount);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref writeOffset, dataOffset);
            ByteWriter.WriteByte(this.SMBParameters, ref writeOffset, setupCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref writeOffset, (ushort)Function);
            ByteWriter.WriteBytes(this.SMBParameters, ref writeOffset, Setup);

            this.SMBData = new byte[padding1 + parameterCount + padding2 + dataCount];
            ByteWriter.WriteBytes(this.SMBData, padding1, TransParameters);
            ByteWriter.WriteBytes(this.SMBData, (int)(padding1 + parameterCount + padding2), TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_NT_TRANSACT;
            }
        }
    }
}