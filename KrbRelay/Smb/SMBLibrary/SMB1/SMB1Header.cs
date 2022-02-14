/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.SMB1
{
    public class SMB1Header
    {
        public const int Length = 32;
        public static readonly byte[] ProtocolSignature = new byte[] { 0xFF, 0x53, 0x4D, 0x42 };

        private byte[] Protocol; // byte[4], 0xFF followed by "SMB"
        public CommandName Command;
        public NTStatus Status;
        public HeaderFlags Flags;
        public HeaderFlags2 Flags2;

        //ushort PIDHigh
        public ulong SecurityFeatures;

        // public ushort Reserved;
        public ushort TID; // Tree ID

        //ushort PIDLow;
        public ushort UID; // User ID

        public ushort MID; // Multiplex ID

        public uint PID; // Process ID

        public SMB1Header()
        {
            Protocol = ProtocolSignature;
        }

        public SMB1Header(byte[] buffer)
        {
            Protocol = ByteReader.ReadBytes(buffer, 0, 4);
            Command = (CommandName)ByteReader.ReadByte(buffer, 4);
            Status = (NTStatus)LittleEndianConverter.ToUInt32(buffer, 5);
            Flags = (HeaderFlags)ByteReader.ReadByte(buffer, 9);
            Flags2 = (HeaderFlags2)LittleEndianConverter.ToUInt16(buffer, 10);
            ushort PIDHigh = LittleEndianConverter.ToUInt16(buffer, 12);
            SecurityFeatures = LittleEndianConverter.ToUInt64(buffer, 14);
            TID = LittleEndianConverter.ToUInt16(buffer, 24);
            ushort PIDLow = LittleEndianConverter.ToUInt16(buffer, 26);
            UID = LittleEndianConverter.ToUInt16(buffer, 28);
            MID = LittleEndianConverter.ToUInt16(buffer, 30);

            PID = (uint)((PIDHigh << 16) | PIDLow);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            ushort PIDHigh = (ushort)(PID >> 16);
            ushort PIDLow = (ushort)(PID & 0xFFFF);

            ByteWriter.WriteBytes(buffer, offset + 0, Protocol);
            ByteWriter.WriteByte(buffer, offset + 4, (byte)Command);
            LittleEndianWriter.WriteUInt32(buffer, offset + 5, (uint)Status);
            ByteWriter.WriteByte(buffer, offset + 9, (byte)Flags);
            LittleEndianWriter.WriteUInt16(buffer, offset + 10, (ushort)Flags2);
            LittleEndianWriter.WriteUInt16(buffer, offset + 12, PIDHigh);
            LittleEndianWriter.WriteUInt64(buffer, offset + 14, SecurityFeatures);
            LittleEndianWriter.WriteUInt16(buffer, offset + 24, TID);
            LittleEndianWriter.WriteUInt16(buffer, offset + 26, PIDLow);
            LittleEndianWriter.WriteUInt16(buffer, offset + 28, UID);
            LittleEndianWriter.WriteUInt16(buffer, offset + 30, MID);
        }

        public byte[] GetBytes()
        {
            byte[] buffer = new byte[Length];
            WriteBytes(buffer, 0);
            return buffer;
        }

        public bool ReplyFlag
        {
            get
            {
                return (Flags & HeaderFlags.Reply) > 0;
            }
        }

        /// <summary>
        /// SMB_FLAGS2_EXTENDED_SECURITY
        /// </summary>
        public bool ExtendedSecurityFlag
        {
            get
            {
                return (this.Flags2 & HeaderFlags2.ExtendedSecurity) > 0;
            }
            set
            {
                if (value)
                {
                    this.Flags2 |= HeaderFlags2.ExtendedSecurity;
                }
                else
                {
                    this.Flags2 &= ~HeaderFlags2.ExtendedSecurity;
                }
            }
        }

        public bool UnicodeFlag
        {
            get
            {
                return (Flags2 & HeaderFlags2.Unicode) > 0;
            }
            set
            {
                if (value)
                {
                    this.Flags2 |= HeaderFlags2.Unicode;
                }
                else
                {
                    this.Flags2 &= ~HeaderFlags2.Unicode;
                }
            }
        }

        public static bool IsValidSMB1Header(byte[] buffer)
        {
            if (buffer.Length >= 4)
            {
                byte[] protocol = ByteReader.ReadBytes(buffer, 0, 4);
                return ByteUtils.AreByteArraysEqual(protocol, ProtocolSignature);
            }
            return false;
        }
    }
}