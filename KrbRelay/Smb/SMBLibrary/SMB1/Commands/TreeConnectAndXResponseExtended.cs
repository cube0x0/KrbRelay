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
    /// SMB_COM_TREE_CONNECT_ANDX Extended Response
    /// </summary>
    public class TreeConnectAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 14;

        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public OptionalSupportFlags OptionalSupport;

        public AccessMask MaximalShareAccessRights;
        public AccessMask GuestMaximalShareAccessRights;

        // Data:
        public ServiceName Service;     // OEM String

        public string NativeFileSystem; // SMB_STRING

        public TreeConnectAndXResponseExtended() : base()
        {
        }

        public TreeConnectAndXResponseExtended(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            int parametersOffset = 4;
            OptionalSupport = (OptionalSupportFlags)LittleEndianReader.ReadUInt16(this.SMBParameters, ref parametersOffset);
            MaximalShareAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(this.SMBParameters, ref parametersOffset);
            GuestMaximalShareAccessRights = (AccessMask)LittleEndianReader.ReadUInt32(this.SMBParameters, ref parametersOffset);

            int dataOffset = 0;
            string serviceString = ByteReader.ReadNullTerminatedAnsiString(this.SMBData, ref dataOffset);
            NativeFileSystem = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);

            Service = ServiceNameHelper.GetServiceName(serviceString);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            int parametersOffset = 4;
            LittleEndianWriter.WriteUInt16(this.SMBParameters, ref parametersOffset, (ushort)OptionalSupport);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref parametersOffset, (uint)MaximalShareAccessRights);
            LittleEndianWriter.WriteUInt32(this.SMBParameters, ref parametersOffset, (uint)GuestMaximalShareAccessRights);

            // Should be written as OEM string but it doesn't really matter
            string serviceString = ServiceNameHelper.GetServiceString(Service);
            if (isUnicode)
            {
                this.SMBData = new byte[serviceString.Length + NativeFileSystem.Length * 2 + 3];
            }
            else
            {
                this.SMBData = new byte[serviceString.Length + NativeFileSystem.Length + 2];
            }

            int offset = 0;
            ByteWriter.WriteNullTerminatedAnsiString(this.SMBData, ref offset, serviceString);
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeFileSystem);

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