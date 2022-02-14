/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_LOCKING_ANDX Response
    /// </summary>
    public class LockingAndXResponse : SMBAndXCommand
    {
        public const int ParametersLength = 4;

        public LockingAndXResponse() : base()
        {
        }

        public LockingAndXResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
        }

        public override byte[] GetBytes(bool isUnicode)
        {
            this.SMBParameters = new byte[ParametersLength];
            return base.GetBytes(isUnicode);
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_LOCKING_ANDX;
            }
        }
    }
}