/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using Utilities;

namespace SMBLibrary.RPC
{
    public class RPCHelper
    {
        /// <summary>
        /// Read port_any_t string structure
        /// </summary>
        public static string ReadPortAddress(byte[] buffer, int offset)
        {
            ushort length = LittleEndianConverter.ToUInt16(buffer, offset + 0);
            // The length includes the C NULL string termination
            return ByteReader.ReadAnsiString(buffer, offset + 2, length - 1);
        }

        public static string ReadPortAddress(byte[] buffer, ref int offset)
        {
            string result = ReadPortAddress(buffer, offset);
            offset += result.Length + 3;
            return result;
        }

        public static void WritePortAddress(byte[] buffer, int offset, string value)
        {
            ushort length = (ushort)(value.Length + 1);
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, length);
            ByteWriter.WriteNullTerminatedAnsiString(buffer, offset + 2, value);
        }

        public static void WritePortAddress(byte[] buffer, ref int offset, string value)
        {
            WritePortAddress(buffer, offset, value);
            offset += value.Length + 3;
        }
    }
}