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
    /// SMB_COM_TREE_CONNECT_ANDX Request
    /// </summary>
    public class TreeConnectAndXRequest : SMBAndXCommand
    {
        public const int ParametersLength = 8;

        // Parameters:
        public TreeConnectFlags Flags;

        // ushort PasswordLength;
        // Data:
        public byte[] Password;

        // Padding
        public string Path;         // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public ServiceName Service; // OEM string

        public TreeConnectAndXRequest()
        {
            Password = new byte[0];
        }

        public TreeConnectAndXRequest(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            int parametersOffset = 4;
            Flags = (TreeConnectFlags)LittleEndianReader.ReadUInt16(this.SMBParameters, ref parametersOffset);
            ushort passwordLength = LittleEndianReader.ReadUInt16(this.SMBParameters, ref parametersOffset);

            int dataOffset = 0;
            Password = ByteReader.ReadBytes(this.SMBData, ref dataOffset, passwordLength);
            if (isUnicode)
            {
                // wordCount is 1 byte
                int padding = (1 + passwordLength) % 2;
                dataOffset += padding;
            }
            Path = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            // Should be read as OEM string but it doesn't really matter
            string serviceString = ByteReader.ReadNullTerminatedAnsiString(this.SMBData, ref dataOffset);
            Service = ServiceNameHelper.GetServiceName(serviceString);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            ushort passwordLength = (ushort)Password.Length;

            this.SMBParameters = new byte[ParametersLength];
            int parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, (ushort)Flags);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, passwordLength);

            string serviceString = ServiceNameHelper.GetServiceString(Service);
            int dataLength = Password.Length + serviceString.Length + 1;
            if (isUnicode)
            {
                int padding = (1 + passwordLength) % 2;
                dataLength += Path.Length * 2 + 2 + padding;
            }
            else
            {
                dataLength += Path.Length + 1;
            }
            this.SMBData = new byte[dataLength];
            int dataOffset = 0;
            ByteWriter.WriteBytes(this.SMBData, ref dataOffset, Password);
            if (isUnicode)
            {
                // wordCount is 1 byte
                int padding = (1 + passwordLength) % 2;
                dataOffset += padding;
            }
            SMB1Helper.WriteSMBString(this.SMBData, ref dataOffset, isUnicode, Path);
            ByteWriter.WriteNullTerminatedAnsiString(this.SMBData, ref dataOffset, serviceString);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_TREE_CONNECT_ANDX;
            }
        }
    }
}