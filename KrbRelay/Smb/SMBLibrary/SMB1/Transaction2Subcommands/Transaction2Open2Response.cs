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
    /// TRANS2_OPEN2 Response
    /// </summary>
    public class Transaction2Open2Response : Transaction2Subcommand
    {
        public const int ParametersLength = 30;

        // Parameters
        public ushort FID;

        public SMBFileAttributes FileAttributes;
        public DateTime? CreationTime;
        public uint FileDataSize;
        public AccessModeOptions AccessMode;
        public ResourceType ResourceType;
        public NamedPipeStatus NMPipeStatus;
        public ActionTaken ActionTaken;
        public uint Reserved;
        public ushort ExtendedAttributeErrorOffset;
        public uint ExtendedAttributeLength;

        public Transaction2Open2Response() : base()
        {
        }

        public Transaction2Open2Response(byte[] parameters, byte[] data, bool isUnicode) : base()
        {
            FID = LittleEndianConverter.ToUInt16(parameters, 0);
            FileAttributes = (SMBFileAttributes)LittleEndianConverter.ToUInt16(parameters, 2);
            CreationTime = UTimeHelper.ReadNullableUTime(parameters, 4);
            FileDataSize = LittleEndianConverter.ToUInt32(parameters, 8);
            AccessMode = new AccessModeOptions(parameters, 12);
            ResourceType = (ResourceType)LittleEndianConverter.ToUInt16(parameters, 14);
            NMPipeStatus = new NamedPipeStatus(parameters, 16);
            ActionTaken = new ActionTaken(parameters, 18);
            Reserved = LittleEndianConverter.ToUInt32(parameters, 20);
            ExtendedAttributeErrorOffset = LittleEndianConverter.ToUInt16(parameters, 24);
            ExtendedAttributeLength = LittleEndianConverter.ToUInt32(parameters, 26);
        }

        public override byte[] GetParameters(bool isUnicode)
        {
            byte[] parameters = new byte[ParametersLength];
            LittleEndianWriter.WriteUInt16(parameters, 0, FID);
            LittleEndianWriter.WriteUInt16(parameters, 2, (ushort)FileAttributes);
            UTimeHelper.WriteUTime(parameters, 4, CreationTime);
            LittleEndianWriter.WriteUInt32(parameters, 8, FileDataSize);
            AccessMode.WriteBytes(parameters, 12);
            LittleEndianWriter.WriteUInt16(parameters, 14, (ushort)ResourceType);
            NMPipeStatus.WriteBytes(parameters, 16);
            ActionTaken.WriteBytes(parameters, 18);
            LittleEndianWriter.WriteUInt32(parameters, 20, Reserved);
            LittleEndianWriter.WriteUInt16(parameters, 24, ExtendedAttributeErrorOffset);
            LittleEndianWriter.WriteUInt32(parameters, 26, ExtendedAttributeLength);
            return parameters;
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