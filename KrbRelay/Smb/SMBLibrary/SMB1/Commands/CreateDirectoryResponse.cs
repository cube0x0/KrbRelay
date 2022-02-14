/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// SMB_COM_CREATE_DIRECTORY Response.
    /// This command is obsolete.
    /// This command is used by Windows NT4 SP6.
    /// </summary>
    public class CreateDirectoryResponse : SMB1Command
    {
        public CreateDirectoryResponse() : base()
        {
        }

        public CreateDirectoryResponse(byte[] buffer, int offset) : base(buffer, offset, false)
        {
        }

        public override CommandName CommandName
        {
            get
            {
                return CommandName.SMB_COM_CREATE_DIRECTORY;
            }
        }
    }
}