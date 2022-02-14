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
    /// SMB_COM_TRANSACTION Response
    /// </summary>
    public class TransactionResponse : SMB1Command
    {
        public const int FixedSMBParametersLength = 20;

        // Parameters:
        public ushort TotalParameterCount;

        public ushort TotalDataCount;
        public ushort Reserved1;

        //ushort ParameterCount;
        //ushort ParameterOffset;
        public ushort ParameterDisplacement;

        //ushort DataCount;
        //ushort DataOffset;
        public ushort DataDisplacement;

        //byte SetupCount; // In 2-byte words
        public byte Reserved2;

        public byte[] Setup;

        // Data:
        // Padding (alignment to 4 byte boundary)
        public byte[] TransParameters; // Trans_Parameters

        // Padding (alignment to 4 byte boundary)
        public byte[] TransData; // Trans_Data

        public TransactionResponse() : base()
        {
            Setup = new byte[0];
            TransParameters = new byte[0];
            TransData = new byte[0];
        }

        public TransactionResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            TotalParameterCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            TotalDataCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 2);
            Reserved1 = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            ushort parameterCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);
            ushort parameterOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 8);
            ParameterDisplacement = LittleEndianConverter.ToUInt16(this.SMBParameters, 10);
            ushort dataCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 12);
            ushort dataOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 14);
            DataDisplacement = LittleEndianConverter.ToUInt16(this.SMBParameters, 16);
            byte setupCount = ByteReader.ReadByte(this.SMBParameters, 18);
            Reserved2 = ByteReader.ReadByte(this.SMBParameters, 19);
            Setup = ByteReader.ReadBytes(this.SMBParameters, 20, setupCount * 2);

            TransParameters = ByteReader.ReadBytes(buffer, parameterOffset, parameterCount);
            TransData = ByteReader.ReadBytes(buffer, dataOffset, dataCount);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            if (TransData.Length > UInt16.MaxValue)
            {
                throw new ArgumentException("Invalid Trans_Data length");
            }
            byte setupCount = (byte)(Setup.Length / 2);
            ushort parameterCount = (ushort)TransParameters.Length;
            ushort dataCount = (ushort)TransData.Length;

            // WordCount + ByteCount are additional 3 bytes
            ushort parameterOffset = (ushort)(SMB1Header.Length + 3 + (FixedSMBParametersLength + Setup.Length));
            int padding1 = (4 - (parameterOffset % 4)) % 4;
            parameterOffset += (ushort)padding1;
            ushort dataOffset = (ushort)(parameterOffset + parameterCount);
            int padding2 = (4 - (dataOffset % 4)) % 4;
            dataOffset += (ushort)padding2;

            this.SMBParameters = new byte[FixedSMBParametersLength + Setup.Length];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, TotalParameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 2, TotalDataCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, Reserved1);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, parameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, parameterOffset);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 10, ParameterDisplacement);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 12, dataCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, dataOffset);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 16, DataDisplacement);
            ByteWriter.WriteByte(this.SMBParameters, 18, setupCount);
            ByteWriter.WriteByte(this.SMBParameters, 19, Reserved2);
            ByteWriter.WriteBytes(this.SMBParameters, 20, Setup);

            this.SMBData = new byte[parameterCount + dataCount + padding1 + padding2];
            ByteWriter.WriteBytes(this.SMBData, padding1, TransParameters);
            ByteWriter.WriteBytes(this.SMBData, padding1 + parameterCount + padding2, TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_TRANSACTION;
            }
        }

        public static int CalculateMessageSize(int setupLength, int trans2ParametersLength, int trans2DataLength)
        {
            int parameterOffset = SMB1Header.Length + 3 + (FixedSMBParametersLength + setupLength);
            int padding1 = (4 - (parameterOffset % 4)) % 4;
            parameterOffset += padding1;
            int dataOffset = (parameterOffset + trans2ParametersLength);
            int padding2 = (4 - (dataOffset % 4)) % 4;

            int messageParametersLength = FixedSMBParametersLength + setupLength;
            int messageDataLength = trans2ParametersLength + trans2DataLength + padding1 + padding2;
            // WordCount + ByteCount are additional 3 bytes
            return SMB1Header.Length + messageParametersLength + messageDataLength + 3;
        }
    }
}