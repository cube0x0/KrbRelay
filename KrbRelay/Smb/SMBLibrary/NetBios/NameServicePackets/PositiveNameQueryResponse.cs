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
    /// [RFC 1002] 4.2.13. POSITIVE NAME QUERY RESPONSE
    /// </summary>
    public class PositiveNameQueryResponse
    {
        public const int EntryLength = 6;

        public NameServicePacketHeader Header;
        public ResourceRecord Resource;

        // Resource Data:
        public KeyValuePairList<byte[], NameFlags> Addresses = new KeyValuePairList<byte[], NameFlags>();

        public PositiveNameQueryResponse()
        {
            Header = new NameServicePacketHeader();
            Header.Flags = OperationFlags.AuthoritativeAnswer | OperationFlags.RecursionDesired;
            Header.OpCode = NameServiceOperation.QueryResponse;
            Header.ANCount = 1;
            Resource = new ResourceRecord(NameRecordType.NB);
        }

        public PositiveNameQueryResponse(byte[] buffer, int offset)
        {
            Header = new NameServicePacketHeader(buffer, ref offset);
            Resource = new ResourceRecord(buffer, ref offset);
            int position = 0;
            while (position < Resource.Data.Length)
            {
                NameFlags nameFlags = (NameFlags)BigEndianReader.ReadUInt16(Resource.Data, ref position);
                byte[] address = ByteReader.ReadBytes(Resource.Data, ref position, 4);
                Addresses.Add(address, nameFlags);
            }
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
            byte[] data = new byte[EntryLength * Addresses.Count];
            int offset = 0;
            foreach (KeyValuePair<byte[], NameFlags> entry in Addresses)
            {
                BigEndianWriter.WriteUInt16(data, ref offset, (ushort)entry.Value);
                ByteWriter.WriteBytes(data, ref offset, entry.Key, 4);
            }
            return data;
        }
    }
}