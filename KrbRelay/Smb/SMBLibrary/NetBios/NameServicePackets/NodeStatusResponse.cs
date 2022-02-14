/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.18. NODE STATUS RESPONSE
    /// </summary>
    public class NodeStatusResponse
    {
        public NameServicePacketHeader Header;
        public ResourceRecord Resource;

        // Resource Data:
        // byte NumberOfNames;
        public KeyValuePairList<string, NameFlags> Names = new KeyValuePairList<string, NameFlags>();

        public NodeStatistics Statistics;

        public NodeStatusResponse()
        {
            Header = new NameServicePacketHeader();
            Header.OpCode = NameServiceOperation.QueryResponse;
            Header.Flags = OperationFlags.AuthoritativeAnswer | OperationFlags.RecursionAvailable;
            Header.ANCount = 1;
            Resource = new ResourceRecord(NameRecordType.NBStat);
            Statistics = new NodeStatistics();
        }

        public NodeStatusResponse(byte[] buffer, int offset)
        {
            Header = new NameServicePacketHeader(buffer, ref offset);
            Resource = new ResourceRecord(buffer, ref offset);

            int position = 0;
            byte numberOfNames = ByteReader.ReadByte(Resource.Data, ref position);
            for (int index = 0; index < numberOfNames; index++)
            {
                string name = ByteReader.ReadAnsiString(Resource.Data, ref position, 16);
                NameFlags nameFlags = (NameFlags)BigEndianReader.ReadUInt16(Resource.Data, ref position);
                Names.Add(name, nameFlags);
            }
            Statistics = new NodeStatistics(Resource.Data, ref position);
        }

        public byte[] GetBytes()
        {
            Resource.Data = GetData();

            MemoryStream stream = new MemoryStream();
            Header.WriteBytes(stream);
            Resource.WriteBytes(stream);
            return stream.ToArray();
        }

        private byte[] GetData()
        {
            MemoryStream stream = new MemoryStream();
            stream.WriteByte((byte)Names.Count);
            foreach (KeyValuePair<string, NameFlags> entry in Names)
            {
                ByteWriter.WriteAnsiString(stream, entry.Key);
                BigEndianWriter.WriteUInt16(stream, (ushort)entry.Value);
            }

            ByteWriter.WriteBytes(stream, Statistics.GetBytes());

            return stream.ToArray();
        }
    }
}