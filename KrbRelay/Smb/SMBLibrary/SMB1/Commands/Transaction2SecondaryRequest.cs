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
    /// SMB_COM_TRANSACTION2_SECONDARY Request
    /// </summary>
    public class Transaction2SecondaryRequest : TransactionSecondaryRequest
    {
        public new const int SMBParametersLength = 18;

        // Parameters:
        public ushort FID;

        public Transaction2SecondaryRequest() : base()
        {
        }

        public Transaction2SecondaryRequest(byte[] buffer, int offset) : base(buffer, offset)
        {
            TotalParameterCount = LittleEndianConverter.ToUInt16(this.SMBData, 0);
            TotalDataCount = LittleEndianConverter.ToUInt16(this.SMBData, 2);
            ParameterCount = LittleEndianConverter.ToUInt16(this.SMBData, 4);
            ParameterOffset = LittleEndianConverter.ToUInt16(this.SMBData, 6);
            ParameterDisplacement = LittleEndianConverter.ToUInt16(this.SMBData, 8);
            DataCount = LittleEndianConverter.ToUInt16(this.SMBData, 10);
            DataOffset = LittleEndianConverter.ToUInt16(this.SMBData, 12);
            DataDisplacement = LittleEndianConverter.ToUInt16(this.SMBData, 14);
            FID = LittleEndianConverter.ToUInt16(this.SMBData, 16);

            TransParameters = ByteReader.ReadBytes(buffer, ParameterOffset, ParameterCount);
            TransData = ByteReader.ReadBytes(buffer, DataOffset, DataCount);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            ParameterCount = (ushort)TransParameters.Length;
            DataCount = (ushort)TransData.Length;

            ParameterOffset = (ushort)(SMB1Header.Length + SMBParametersLength);
            int padding1 = (4 - (ParameterOffset % 4)) % 4;
            ParameterOffset += (ushort)padding1;
            DataOffset = (ushort)(ParameterOffset + ParameterCount);
            int padding2 = (4 - (DataOffset % 4)) % 4;
            DataOffset += (ushort)padding2;

            this.SMBParameters = new byte[SMBParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, TotalParameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 2, TotalDataCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, ParameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, ParameterOffset);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 8, ParameterDisplacement);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 10, DataCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 12, DataOffset);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 14, DataDisplacement);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 16, FID);

            this.SMBData = new byte[ParameterCount + DataCount + padding1 + padding2];
            ByteWriter.WriteBytes(this.SMBData, padding1, TransParameters);
            ByteWriter.WriteBytes(this.SMBData, padding1 + ParameterCount + padding2, TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_TRANSACTION2_SECONDARY;
            }
        }
    }
}