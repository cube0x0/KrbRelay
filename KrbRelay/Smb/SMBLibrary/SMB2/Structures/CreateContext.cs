/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// [MS-SMB2] 2.2.13.2 - SMB2_CREATE_CONTEXT
    /// </summary>
    public class CreateContext
    {
        public const int FixedLength = 16;

        /// <summary>
        /// The offset from the beginning of this Create Context to the beginning of a subsequent 8-byte aligned Create Context.
        /// This field MUST be set to 0 if there are no subsequent contexts.
        /// </summary>
        public uint Next;

        private ushort NameOffset; // The offset from the beginning of this structure to the 8-byte aligned name value
        private ushort NameLength;
        public ushort Reserved;
        private ushort DataOffset; // The offset from the beginning of this structure to the 8-byte aligned data payload
        private uint DataLength;
        public string Name = String.Empty;
        public byte[] Data = new byte[0];

        public CreateContext()
        {
        }

        public CreateContext(byte[] buffer, int offset)
        {
            Next = LittleEndianConverter.ToUInt32(buffer, offset + 0);
            NameOffset = LittleEndianConverter.ToUInt16(buffer, offset + 4);
            NameLength = LittleEndianConverter.ToUInt16(buffer, offset + 6);
            Reserved = LittleEndianConverter.ToUInt16(buffer, offset + 8);
            DataOffset = LittleEndianConverter.ToUInt16(buffer, offset + 10);
            DataLength = LittleEndianConverter.ToUInt32(buffer, offset + 12);
            if (NameLength > 0)
            {
                Name = ByteReader.ReadUTF16String(buffer, offset + NameOffset, NameLength / 2);
            }
            if (DataLength > 0)
            {
                Data = ByteReader.ReadBytes(buffer, offset + DataOffset, (int)DataLength);
            }
        }

        private void WriteBytes(byte[] buffer, int offset)
        {
            LittleEndianWriter.WriteUInt32(buffer, offset + 0, Next);
            NameOffset = 0;
            NameLength = (ushort)(Name.Length * 2);
            if (Name.Length > 0)
            {
                NameOffset = (ushort)FixedLength;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 4, NameOffset);
            LittleEndianWriter.WriteUInt16(buffer, offset + 6, NameLength);
            LittleEndianWriter.WriteUInt16(buffer, offset + 8, Reserved);
            DataOffset = 0;
            DataLength = (uint)Data.Length;
            if (Data.Length > 0)
            {
                int paddedNameLength = (int)Math.Ceiling((double)(Name.Length * 2) / 8) * 8;
                DataOffset = (ushort)(FixedLength + paddedNameLength);
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 10, DataOffset);
            ByteWriter.WriteUTF16String(buffer, NameOffset, Name);
            ByteWriter.WriteBytes(buffer, DataOffset, Data);
        }

        public int Length
        {
            get
            {
                if (Data.Length > 0)
                {
                    int paddedNameLength = (int)Math.Ceiling((double)(Name.Length * 2) / 8) * 8;
                    return FixedLength + paddedNameLength + Data.Length;
                }
                else
                {
                    return FixedLength + Name.Length * 2;
                }
            }
        }

        public static List<CreateContext> ReadCreateContextList(byte[] buffer, int offset)
        {
            List<CreateContext> result = new List<CreateContext>();
            CreateContext createContext;
            do
            {
                createContext = new CreateContext(buffer, offset);
                result.Add(createContext);
                offset += (int)createContext.Next;
            }
            while (createContext.Next != 0);

            return result;
        }

        public static void WriteCreateContextList(byte[] buffer, int offset, List<CreateContext> createContexts)
        {
            for (int index = 0; index < createContexts.Count; index++)
            {
                CreateContext createContext = createContexts[index];
                int length = createContext.Length;
                int paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                if (index < createContexts.Count - 1)
                {
                    createContext.Next = (uint)paddedLength;
                }
                else
                {
                    createContext.Next = 0;
                }
                createContext.WriteBytes(buffer, offset);
                offset += paddedLength;
            }
        }

        public static int GetCreateContextListLength(List<CreateContext> createContexts)
        {
            int result = 0;
            for (int index = 0; index < createContexts.Count; index++)
            {
                CreateContext createContext = createContexts[index];
                int length = createContext.Length;
                if (index < createContexts.Count - 1)
                {
                    int paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                    result += paddedLength;
                }
                else
                {
                    result += length;
                }
            }
            return result;
        }
    }
}