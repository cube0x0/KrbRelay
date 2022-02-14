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
    /// SMB_COM_SESSION_SETUP_ANDX Response
    /// </summary>
    public class SessionSetupAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 6;

        // Parameters:
        // CommandName AndXCommand;
        // byte AndXReserved;
        // ushort AndXOffset;
        public SessionSetupAction Action;

        // Data:
        public string NativeOS;      // SMB_STRING (If Unicode, this field MUST be aligned to start on a 2-byte boundary from the start of the SMB header)

        public string NativeLanMan;  // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)
        public string PrimaryDomain; // SMB_STRING (this field WILL be aligned to start on a 2-byte boundary from the start of the SMB header)

        public SessionSetupAndXResponse() : base()
        {
            NativeOS = String.Empty;
            NativeLanMan = String.Empty;
            PrimaryDomain = String.Empty;
        }

        public SessionSetupAndXResponse(byte[] buffer, int offset, bool isUnicode) : base(buffer, offset, isUnicode)
        {
            Action = (SessionSetupAction)LittleEndianConverter.ToUInt16(this.SMBParameters, 4);

            int dataOffset = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                dataOffset++;
            }
            NativeOS = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            NativeLanMan = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
            if ((this.SMBData.Length - dataOffset) % 2 == 1)
            {
                // Workaround for a single terminating null byte
                this.SMBData = ByteUtils.Concatenate(this.SMBData, new byte[1]);
            }
            PrimaryDomain = SMB1Helper.ReadSMBString(this.SMBData, ref dataOffset, isUnicode);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 4, (ushort)Action);

            int offset = 0;
            if (isUnicode)
            {
                // A Unicode string MUST be aligned to a 16-bit boundary with respect to the beginning of the SMB Header.
                // Note: SMBData starts at an odd offset.
                int padding = 1;
                this.SMBData = new byte[padding + NativeOS.Length * 2 + NativeLanMan.Length * 2 + PrimaryDomain.Length * 2 + 6];
                offset = padding;
            }
            else
            {
                this.SMBData = new byte[NativeOS.Length + NativeLanMan.Length + PrimaryDomain.Length + 3];
            }
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeOS);
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, NativeLanMan);
            SMB1Helper.WriteSMBString(this.SMBData, ref offset, isUnicode, PrimaryDomain);

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