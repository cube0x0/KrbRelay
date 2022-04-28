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
    /// SMB_COM_TREE_CONNECT_ANDX Response
    /// </summary>
    public class TreeConnectAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 6;

        // Parameters:
        //CommandName AndXCommand;
        //byte AndXReserved;
        //ushort AndXOffset;
        public OptionalSupportFlags OptionalSupport;

        // Data:
        public ServiceName Service;     // OEM String

        public string NativeFileSystem; // SMB_STRING

        public TreeConnectAndXResponse() : base()
        {
        }

        public TreeConnectAndXResponse(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            OptionalSupport = (OptionalSupportFlags)LittleEndianConverter.ToUInt16(SMBParameters, 4);

            int dataOffset = 0;
            string serviceString = ByteReader.ReadNullTerminatedAnsiString(SMBData, ref dataOffset);
            NativeFileSystem = SMB1Helper.ReadSMBString(SMBData, ref dataOffset, isUnicode);

            Service = ServiceNameHelper.GetServiceName(serviceString);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(SMBParameters, 4, (ushort)OptionalSupport);

            // Should be written as OEM string but it doesn't really matter
            string serviceString = ServiceNameHelper.GetServiceString(Service);
            if (isUnicode)
            {
                SMBData = new byte[serviceString.Length + NativeFileSystem.Length * 2 + 3];
            }
            else
            {
                SMBData = new byte[serviceString.Length + NativeFileSystem.Length + 2];
            }

            int offset = 0;
            ByteWriter.WriteNullTerminatedAnsiString(SMBData, ref offset, serviceString);
            SMB1Helper.WriteSMBString(SMBData, ref offset, isUnicode, NativeFileSystem);

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