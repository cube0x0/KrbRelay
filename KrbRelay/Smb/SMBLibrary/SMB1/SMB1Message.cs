/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    /// <summary>
    /// Each message has a single header and either a single command or multiple batched (AndX) commands.
    /// Multiple command requests or responses can be sent in a single message.
    /// </summary>
    public class SMB1Message
    {
        public SMB1Header Header;
        public List<SMB1Command> Commands = new List<SMB1Command>();

        public SMB1Message()
        {
            Header = new SMB1Header();
        }

        public SMB1Message(byte[] buffer)
        {
            Header = new SMB1Header(buffer);
            SMB1Command command = SMB1Command.ReadCommand(buffer, SMB1Header.Length, Header.Command, Header);
            Commands.Add(command);
            while (command is SMBAndXCommand)
            {
                SMBAndXCommand andXCommand = (SMBAndXCommand)command;
                if (andXCommand.AndXCommand == CommandName.SMB_COM_NO_ANDX_COMMAND)
                {
                    break;
                }
                command = SMB1Command.ReadCommand(buffer, andXCommand.AndXOffset, andXCommand.AndXCommand, Header);
                Commands.Add(command);
            }
        }

        public byte[] GetBytes()
        {
            if (Commands.Count == 0)
            {
                throw new ArgumentException("Invalid command sequence");
            }

            for (int index = 0; index < Commands.Count - 1; index++)
            {
                if (!(Commands[index] is SMBAndXCommand))
                {
                    throw new ArgumentException("Invalid command sequence");
                }
            }

            SMB1Command lastCommand = Commands[Commands.Count - 1];
            if (lastCommand is SMBAndXCommand)
            {
                ((SMBAndXCommand)lastCommand).AndXCommand = CommandName.SMB_COM_NO_ANDX_COMMAND;
            }

            List<byte[]> sequence = new List<byte[]>();
            int length = SMB1Header.Length;
            byte[] commandBytes;
            for (int index = 0; index < Commands.Count - 1; index++)
            {
                SMBAndXCommand andXCommand = (SMBAndXCommand)Commands[index];
                andXCommand.AndXCommand = Commands[index + 1].CommandName;
                commandBytes = Commands[index].GetBytes(Header.UnicodeFlag);
                ushort nextOffset = (ushort)(length + commandBytes.Length);
                SMBAndXCommand.WriteAndXOffset(commandBytes, 0, nextOffset);
                sequence.Add(commandBytes);
                length += commandBytes.Length;
            }

            commandBytes = lastCommand.GetBytes(Header.UnicodeFlag);
            sequence.Add(commandBytes);
            length += commandBytes.Length;

            Header.Command = Commands[0].CommandName;

            byte[] buffer = new byte[length];
            Header.WriteBytes(buffer, 0);
            int offset = SMB1Header.Length;
            foreach (byte[] bytes in sequence)
            {
                ByteWriter.WriteBytes(buffer, ref offset, bytes);
            }

            return buffer;
        }

        public static SMB1Message GetSMB1Message(byte[] buffer)
        {
            if (!SMB1Header.IsValidSMB1Header(buffer))
            {
                throw new InvalidDataException("Invalid SMB header signature");
            }
            return new SMB1Message(buffer);
        }
    }
}