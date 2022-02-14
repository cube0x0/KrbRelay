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
    /// SMB_COM_SESSION_SETUP_ANDX Response, NT LAN Manager dialect, Extended Security response
    /// </summary>
    public class SessionSetupAndXResponseExtended : SMBAndXCommand
    {
        public const int ParametersLength = 8;

        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public SessionSetupAction Action;

        private ushort SecurityBlobLength;

        // Data:
        public byte[] SecurityBlob;

        public string NativeOS;     // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string NativeLanMan; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public SessionSetupAndXResponseExtended() : base()
        {
            SecurityBlob = new byte[0];
            NativeOS = String.Empty;
            NativeLanMan = String.Empty;
        }

        public SessionSetupAndXResponseExtended(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            Action = (SessionSetupAction)LittleEndianConverter.ToUInt16(this.SMBParameters, 4);
            SecurityBlobLength = LittleEndianConverter.ToUInt16(this.SMBParameters, 6);

            SecurityBlob = ByteReader.ReadBytes(this.SMBData, 0, SecurityBlobLength);

            int dataOffset = SecurityBlob.Length;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                int padding = (1 + SecurityBlobLength) % 2;
                dataOffset += padding;
            }
            NativeOS = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            if ((this.SMBData.Length - dataOffset) % 2 == 1)
            {
                // Workaround for a single terminating null byte
                this.SMBData = ByteUtils.Concatenate(this.SMBData, new byte[1]);
            }
            NativeLanMan = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            ushort securityBlobLength = (ushort)SecurityBlob.Length;

            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, (ushort)Action);
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 6, securityBlobLength);

            int padding = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                padding = (1 + securityBlobLength) % 2;
                this.SMBData = new byte[SecurityBlob.Length + padding + NativeOS.Length * 2 + NativeLanMan.Length * 2 + 4];
            }
            else
            {
                this.SMBData = new byte[SecurityBlob.Length + NativeOS.Length + NativeLanMan.Length + 2];
            }
            int offset = 0;
            ByteWriter.WriteBytes(this.SMBData, ref offset, SecurityBlob);
            offset += padding;
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeOS);
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeLanMan);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_SESSION_SETUP_ANDX;
            }
        }
    }
}