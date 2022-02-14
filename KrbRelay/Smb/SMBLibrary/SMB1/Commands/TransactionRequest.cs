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
    /// SMB_COM_TRANSACTION Request
    /// </summary>
    public class TransactionRequest : SMB1Command
    {
        public const int FixedSMBParametersLength = 28;

        // Parameters:
        public ushort TotalParameterCount;

        public ushort TotalDataCount;
        public ushort MaxParameterCount;
        public ushort MaxDataCount;
        public byte MaxSetupCount;
        public byte Reserved1;
        public TransactionFlags Flags;
        public uint Timeout;
        public ushort Reserved2;

        // ushort ParameterCount;
        // ushort ParameterOffset;
        // ushort DataCount;
        // ushort DataOffset;
        // byte SetupCount; // In 2-byte words
        public byte Reserved3;

        public byte[] Setup;

        // Data:
        public string Name; // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        // Padding (alignment to 4 byte boundary)
        public byte[] TransParameters; // Trans_Parameters

        // Padding (alignment to 4 byte boundary)
        public byte[] TransData; // Trans_Data

        public TransactionRequest() : base()
        {
            Name = String.Empty;
        }

        public TransactionRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            TotalParameterCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            TotalDataCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 2);
            MaxParameterCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            MaxDataCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);
            MaxSetupCount = ByteReader.ReadByte(this.SMBParameters, 8);
            Reserved1 = ByteReader.ReadByte(this.SMBParameters, 9);
            Flags = (TransactionFlags)LittleEndianConverter.ToUInt16(this.SMBParameters, 10);
            Timeout = LittleEndianConverter.ToUInt32(this.SMBParameters, 12);
            Reserved2 = LittleEndianConverter.ToUInt16(this.SMBParameters, 16);
            ushort transParameterCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 18);
            ushort transParameterOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 20);
            ushort transDataCount = LittleEndianConverter.ToUInt16(this.SMBParameters, 22);
            ushort transDataOffset = LittleEndianConverter.ToUInt16(this.SMBParameters, 24);
            byte setupCount = ByteReader.ReadByte(this.SMBParameters, 26);
            Reserved3 = ByteReader.ReadByte(this.SMBParameters, 27);
            Setup = ByteReader.ReadBytes(this.SMBParameters, 28, setupCount * 2);

            if (this.SMBData.Length > 0) // Workaround, Some SAMBA clients will set ByteCount to 0 (Popcorn Hour A-400)
            {
                int dataOffset = 0;
                if (this is Transaction2Request)
                {
                    Name = String.Empty;
                    int nameLength = 1;
                    dataOffset += nameLength;
                }
                else
                {
                    if (isUnicode)
                    {
                        int namePadding = 1;
                        dataOffset += namePadding;
                    }
                    Name = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
                }
            }
            TransParameters = ByteReader.ReadBytes(buffer, transParameterOffset, transParameterCount);
            TransData = ByteReader.ReadBytes(buffer, transDataOffset, transDataCount);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            if (Setup.Length % 2 > 0)
            {
                throw new Exception("Setup length must be a multiple of 2");
            }

            byte setupCount = (byte)(Setup.Length / 2);
            ushort transParameterCount = (ushort)TransParameters.Length;
            ushort transDataCount = (ushort)TransData.Length;

            // WordCount + ByteCount are additional 3 bytes
            int nameLength;
            int namePadding;
            if (this is Transaction2Request)
            {
                namePadding = 0;
                nameLength = 1;
            }
            else
            {
                if (isUnicode)
                {
                    namePadding = 1;
                    nameLength = Name.Length * 2 + 2;
                }
                else
                {
                    namePadding = 0;
                    nameLength = Name.Length + 1;
                }
            }
            ushort transParameterOffset = (ushort)(SMB1Header.Length + 3 + (FixedSMBParametersLength + Setup.Length + namePadding + nameLength));
            int padding1 = (4 - (transParameterOffset % 4)) % 4;
            transParameterOffset += (ushort)padding1;
            ushort transDataOffset = (ushort)(transParameterOffset + transParameterCount);
            int padding2 = (4 - (transDataOffset % 4)) % 4;
            transDataOffset += (ushort)padding2;

            this.SMBParameters = new byte[FixedSMBParametersLength + Setup.Length];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, TotalParameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 2, TotalDataCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, MaxParameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, MaxDataCount);
            ByteWriter.WriteByte(this.SMBParameters, 8, MaxSetupCount);
            ByteWriter.WriteByte(this.SMBParameters, 9, Reserved1);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 10, (ushort)Flags);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, 12, Timeout);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 16, Reserved2);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 18, transParameterCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 20, transParameterOffset);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 22, transDataCount);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 24, transDataOffset);
            ByteWriter.WriteByte(this.SMBParameters, 26, setupCount);
            ByteWriter.WriteByte(this.SMBParameters, 27, Reserved3);
            ByteWriter.WriteBytes(this.SMBParameters, 28, Setup);

            int offset;
            this.SMBData = new byte[namePadding + nameLength + padding1 + transParameterCount + padding2 + transDataCount];
            offset = namePadding;
            if (this is Transaction2Request)
            {
                offset += nameLength;
            }
            else
            {
                SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, Name);
            }
            ByteWriter.WriteBytes(this.SMBData, offset + padding1, TransParameters);
            ByteWriter.WriteBytes(this.SMBData, offset + padding1 + transParameterCount + padding2, TransData);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_TRANSACTION;
            }
        }
    }
}