/* Copyright (C) 2014-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;

namespace SMBLibrary.NetBios
{
    /// <summary>
    /// [RFC 1002] 4.2.12. NAME QUERY REQUEST
    /// </summary>
    public class NameQueryRequest
    {
        public NameServicePacketHeader Header;
        public QuestionSection Question;

        public NameQueryRequest()
        {
            Header = new NameServicePacketHeader();
            Header.OpCode = NameServiceOperation.QueryRequest;
            Header.Flags = OperationFlags.RecursionDesired;
            Question = new QuestionSection();
            Question.Type = NameRecordType.NB;
        }

        public NameQueryRequest(byte[] buffer, int offset)
        {
            Header = new NameServicePacketHeader(buffer, ref offset);
            Question = new QuestionSection(buffer, ref offset);
        }

        public byte[] GetBytes()
        {
            MemoryStream stream = new MemoryStream();
            Header.WriteBytes(stream);
            Question.WriteBytes(stream);
            return stream.ToArray();
        }
    }
}