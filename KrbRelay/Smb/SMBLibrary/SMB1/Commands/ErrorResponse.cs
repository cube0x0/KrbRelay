/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// The Command trailer of an error response message.
    /// See [MS-CIFS]3.3.4.1.2 - Sending Any Error Response Message.
    /// </summary>
    public class ErrorResponse : SMB1Command
    {
        private CommandName m_commandName;

        public ErrorResponse(CommandName commandName) : base()
        {
            m_commandName = commandName;
        }

        public override CommandName CommandName
        {
            get
            {
                return m_commandName;
            }
        }
    }
}