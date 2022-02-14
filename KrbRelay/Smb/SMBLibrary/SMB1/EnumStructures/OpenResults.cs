/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public struct OpenResults // 2 bytes
    {
        public const int Length = 2;

        public OpenResult OpenResult;
        public bool OpLockGranted;

        public OpenResults(byte[] buffer, int offset)
        {
            OpenResult = (OpenResult)(buffer[offset + 0] & 0x3);
            OpLockGranted = (buffer[offset + 1] & 0x80) > 0;
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)OpenResult;
            if (OpLockGranted)
            {
                buffer[offset + 1] = 0x80;
            }
            else
            {
                buffer[offset + 1] = 0x00;
            }
        }

        public void WriteBytes(byte[] buffer, ref int offset)
        {
            WriteBytes(buffer, offset);
            offset += Length;
        }

        public static OpenResults Read(byte[] buffer, ref int offset)
        {
            offset += Length;
            return new OpenResults(buffer, offset - Length);
        }
    }
}