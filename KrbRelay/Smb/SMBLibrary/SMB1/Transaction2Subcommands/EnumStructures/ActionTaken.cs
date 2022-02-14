/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public enum LockStatus : byte
    {
        NoOpLockWasRequestedOrGranted = 0x00,
        OpLockWasRequestedAndGranted = 0x01,
    }

    public struct ActionTaken
    {
        public OpenResult OpenResult;
        public LockStatus LockStatus;

        public ActionTaken(byte[] buffer, int offset)
        {
            OpenResult = (OpenResult)(buffer[offset + 0] & 0x03);
            LockStatus = (LockStatus)(buffer[offset + 1] >> 7);
        }

        public void WriteBytes(byte[] buffer, int offset)
        {
            buffer[offset + 0] = (byte)((byte)OpenResult & 0x03);
            buffer[offset + 1] = (byte)((byte)LockStatus << 7);
        }
    }
}