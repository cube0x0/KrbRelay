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
    /// SMB_COM_SET_INFORMATION2 Request
    /// </summary>
    public class SetInformation2Request : SMB1Command
    {
        public const int ParametersLength = 14;

        // Parameters:
        public ushort FID;

        public DateTime? CreationDateTime; // A date and time value of 0 indicates to the server that the values MUST NOT be changed
        public DateTime? LastAccessDateTime; // A date and time value of 0 indicates to the server that the values MUST NOT be changed
        public DateTime? LastWriteDateTime; // A date and time value of 0 indicates to the server that the values MUST NOT be changed

        public SetInformation2Request() : base()
        {
        }

        public SetInformation2Request(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            CreationDateTime = SMB1Helper.ReadNullableSMBDateTime(this.SMBParameters, 2);
            LastAccessDateTime = SMB1Helper.ReadNullableSMBDateTime(this.SMBParameters, 6);
            LastWriteDateTime = SMB1Helper.ReadNullableSMBDateTime(this.SMBParameters, 10);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, FID);
            SMB1Helper.WriteSMBDateTime(this.SMBParameters, 2, CreationDateTime);
            SMB1Helper.WriteSMBDateTime(this.SMBParameters, 6, LastAccessDateTime);
            SMB1Helper.WriteSMBDateTime(this.SMBParameters, 10, LastWriteDateTime);

            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_SET_INFORMATION2;
            }
        }
    }
}