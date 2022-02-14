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
    /// [MS-SMB2] 2.2.3.1 - NEGOTIATE_CONTEXT
    /// </summary>
    public class NegotiateContext
    {
        public const int FixedLength = 8;

        public NegotiateContextType ContextType;
        private ushort DataLength;
        public uint Reserved;
        public byte[] Data = new byte[0];

        public NegotiateContext()
        {
        }

        public NegotiateContext(byte[] buffer, int offset)
        {
            ContextType = (NegotiateContextType)LittleEndianConverter.ToUInt16(buffer, offset + 0);
            DataLength = LittleEndianConverter.ToUInt16(buffer, offset + 2);
            Reserved = LittleEndianConverter.ToUInt32(buffer, offset + 4);
            ByteReader.ReadBytes(buffer, offset + 8, DataLength);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            DataLength = (ushort)Data.Length;
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, (ushort)ContextType);
            LittleEndianWriter.WriteUInt16(buffer, offset + 2, DataLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, Reserved);
            ByteWriter.WriteBytes(buffer, offset + 8, Data);
        }

        public int Length
        {
            get
            {
                return FixedLength + Data.Length;
            }
        }

        public static List<NegotiateContext> ReadNegotiateContextList(byte[] buffer, int offset, int count)
        {
            List<NegotiateContext> result = new List<NegotiateContext>();
            for (int index = 0; index < count; index++)
            {
                NegotiateContext context = new NegotiateContext(buffer, offset);
                result.Add(context);
                offset += context.Length;
            }
            return result;
        }

        public static void WriteNegotiateContextList(byte[] buffer, int offset, List<NegotiateContext> negotiateContextList)
        {
            // Subsequent negotiate contexts MUST appear at the first 8-byte aligned offset following the previous negotiate context
            for (int index = 0; index < negotiateContextList.Count; index++)
            {
                NegotiateContext context = negotiateContextList[index];
                int length = context.Length;
                int paddedLength = (int)Math.Ceiling((double)length / 8) * 8;
                context.WriteBytes(buffer, offset);
                offset += paddedLength;
            }
        }

        public static int GetNegotiateContextListLength(List<NegotiateContext> negotiateContextList)
        {
            int result = 0;
            for (int index = 0; index < negotiateContextList.Count; index++)
            {
                NegotiateContext context = negotiateContextList[index];
                int length = context.Length;
                if (index < negotiateContextList.Count - 1)
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