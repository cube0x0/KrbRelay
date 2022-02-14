/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using System.Net;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.2. NAME REGISTRATION REQUEST
    /// </summary>
    public class NameRegistrationRequest
    {
        public const int DataLength = 6;

        public NameServicePacketHeader Header;
        public QuestionSection Question;
        public ResourceRecord Resource;
        public NameFlags NameFlags;
        public byte[] Address; // IPv4 address

        public NameRegistrationRequest()
        {
            Header = new NameServicePacketHeader();
            Header.OpCode = NameServiceOperation.RegistrationRequest;
            Header.QDCount = 1;
            Header.ARCount = 1;
            Header.Flags = OperationFlags.Broadcast | OperationFlags.RecursionDesired;
            Question = new QuestionSection();
            Resource = new ResourceRecord(NameRecordType.NB);
            Address = new byte[4];
        }

        public NameRegistrationRequest(string machineName, NetBiosSuffix suffix, IPAddress address) : this()
        {
            Question.Name = NetBiosUtils.GetMSNetBiosName(machineName, suffix);
            Address = address.GetAddressBytes();
        }

        public byte[] GetBytes()
        {
            Resource.Data = GetData();

            MemoryStream stream = new MemoryStream();
            Header.WriteBytes(stream);
            Question.WriteBytes(stream);
            Resource.WriteBytes(stream, NameServicePacketHeader.Length);
            return stream.ToArray();
        }

        private byte[] GetData()
        {
            byte[] data = new byte[DataLength];
            BigEndianWriter.WriteUInt16(data, 0, (ushort)NameFlags);
            ByteWriter.WriteBytes(data, 2, Address, 4);
            return data;
        }
    }
}