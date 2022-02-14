/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
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
    /// TRANS2_OPEN2 Request
    /// </summary>
    public class Transaction2Open2Request : Transaction2Subcommand
    {
        // Parameters:
        public Open2Flags Flags;

        public AccessModeOptions AccessMode;
        public ushort Reserved1;
        public SMBFileAttributes FileAttributes;
        public DateTime? CreationTime; // UTIME (seconds since Jan 1, 1970)
        public OpenMode OpenMode;
        public uint AllocationSize;
        public byte[] Reserved; // 10 bytes
        public string FileName; // SMB_STRING

        // Data:
        public FullExtendedAttributeList ExtendedAttributeList;

        public Transaction2Open2Request() : base()
        {
            Reserved = new byte[10];
        }

        public Transaction2Open2Request(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            Flags = (Open2Flags)LittleEndianConverter.ToUInt16(parameters, 0);
            AccessMode = new AccessModeOptions(parameters, 2);
            Reserved1 = LittleEndianConverter.ToUInt16(parameters, 4);
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(parameters, 6);
            CreationTime = UTimeHelper.ReadNullableUTime(parameters, 8);
            OpenMode = new OpenMode(parameters, 12);
            AllocationSize = LittleEndianConverter.ToUInt32(parameters, 14);
            Reserved = ByteReader.ReadBytes(parameters, 18, 10);
            FileName = SMB1Helper.ReadSMBString(parameters, 28, isUnicode);

            ExtendedAttributeList = new FullExtendedAttributeList(data, 0);
        }

        public override byte[] GetSetup()
        {
            return LittleEndianConverter.GetBytes((ushort)SubcommandName);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            int length = 28;
            if (isUnicode)
            {
                length += FileName.Length * 2 + 2;
            }
            else
            {
                length += FileName.Length + 1;
            }

            byte[] parameters = new byte[length];
            LittleEndianWriter.WriteUInt16(parameters, 0, (ushort)Flags);
            AccessMode.WriteBytes(parameters, 2);
            LittleEndianWriter.WriteUInt16(parameters, 4, Reserved1);
            LittleEndianWriter.WriteUInt16(parameters, 6, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(parameters, 8, CreationTime);
            OpenMode.WriteBytes(parameters, 12);
            LittleEndianWriter.WriteUInt32(parameters, 14, AllocationSize);
            ByteWriter.WriteBytes(parameters, 18, Reserved, 10);
            SMB1Helper.WriteSMBString(parameters, 28, isUnicode, FileName);
            return parameters;
        }

        public override byte[] GetData(bool isUnicode)
        {
            return ExtendedAttributeList.GetBytes();
        }

        public override Transaction2SubcommandName SubcommandName
        {
            get
            {
                return Transaction2SubcommandName.TRANS2_OPEN2;
            }
        }
    }
}