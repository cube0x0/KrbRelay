/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.RPC
{
    /// <summary>
    /// p_cont_list_t
    /// Presentation Context List
    /// </summary>
    public class ContextList : List<ContextElement>
    {
        //byte NumberOfContextElements;
        public byte Reserved1;

        public ushort Reserved2;

        public ContextList() : base()
        {
        }

        public ContextList(byte[] buffer, int offset) : base()
        {
            byte numberOfContextElements = ByteReader.ReadByte(buffer, offset + 0);
            Reserved1 = ByteReader.ReadByte(buffer, offset + 1);
            Reserved2 = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            offset += 4;
            for (int index = 0; index < numberOfContextElements; index++)
            {
                ContextElement element = new ContextElement(buffer, offset);
                this.Add(element);
                offset += element.Length;
            }
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            byte numberOfContextElements = (byte)this.Count;

            ByteWriter.WriteByte(buffer, offset + 0, numberOfContextElements);
            ByteWriter.WriteByte(buffer, offset + 1, Reserved1);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, Reserved2);
            offset += 4;
            for (int index = 0; index < numberOfContextElements; index++)
            {
                this[index].WriteBytes(buffer, offset);
                offset += this[index].Length;
            }
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            WriteBytes(buffer, offset);
            offset += this.Length;
        }

        public int Length
        {
            get
            {
                int length = 4;
                for (int index = 0; index < this.Count; index++)
                {
                    length += this[index].Length;
                }
                return length;
            }
        }
    }
}