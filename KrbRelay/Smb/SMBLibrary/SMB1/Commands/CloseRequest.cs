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
    /// SMB_COM_CLOSE Request
    /// </summary>
    public class CloseRequest : SMB1Command
    {
        public const int ParametersLength = 6;

        // Parameters:
        public ushort FID;

        /// <summary>
        /// A value of 0x00000000 or 0xFFFFFFFF results in the server not updating the last modification time
        /// </summary>
        public DateTime? LastTimeModified;

        public CloseRequest() : base()
        {
        }

        public CloseRequest(byte[] buffer, int offset) : base(buffer, offset, false)
        {
            FID = LittleEndianConverter.ToUInt16(this.SMBParameters, 0);
            LastTimeModified = UTimeHelper.ReadNullableUTime(this.SMBParameters, 2);
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(this.SMBParameters, 0, FID);
            UTimeHelper.WriteUTime(this.SMBParameters, 2, LastTimeModified);
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_CLOSE;
            }
        }
    }
}