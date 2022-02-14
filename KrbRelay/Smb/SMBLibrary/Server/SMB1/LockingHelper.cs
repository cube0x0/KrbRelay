/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class LockingHelper
    {
        internal static List<SMB1Command> GetLockingAndXResponse(SMB1Header header, LockingAndXRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Locking failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, request.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return new ErrorResponse(request.CommandName);
            }

            if ((request.TypeOfLock & LockType.CHANGE_LOCKTYPE) > 0)
            {
                // [MS-CIFS] Windows NT Server does not support the CHANGE_LOCKTYPE flag of TypeOfLock.
                state.LogToServer(Severity.Verbose, "Locking failed. CHANGE_LOCKTYPE is not supported.");
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
                return new ErrorResponse(request.CommandName);
            }

            if (request.Unlocks.Count == 0 && request.Locks.Count == 0)
            {
                // [MS-CIFS] If NumberOfRequestedUnlocks and NumberOfRequestedLocks are both zero [..] the server MUST NOT send an SMB_COM_LOCKING_ANDX Response.
                return new List<SMB1Command>();
            }

            // [MS-CIFS] If the CANCEL_LOCK bit is set, Windows NT servers cancel only the first lock request range listed in the lock array.
            for (int lockIndex = 0; lockIndex < request.Unlocks.Count; lockIndex++)
            {
                LockingRange lockingRange = request.Unlocks[lockIndex];
                header.Status = share.FileStore.UnlockFile(openFile.Handle, (long)lockingRange.ByteOffset, (long)lockingRange.LengthInBytes);
                if (header.Status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "Locking: Unlocking '{0}{1}' failed. Offset: {2}, Length: {3}. NTStatus: {4}.", share.Name, openFile.Path, lockingRange.ByteOffset, lockingRange.LengthInBytes, header.Status);
                    return new ErrorResponse(request.CommandName);
                }
                state.LogToServer(Severity.Verbose, "Locking: Unlocking '{0}{1}' succeeded. Offset: {2}, Length: {3}.", share.Name, openFile.Path, lockingRange.ByteOffset, lockingRange.LengthInBytes);
            }

            for (int lockIndex = 0; lockIndex < request.Locks.Count; lockIndex++)
            {
                LockingRange lockingRange = request.Locks[lockIndex];
                bool exclusiveLock = (request.TypeOfLock & LockType.SHARED_LOCK) == 0;
                header.Status = share.FileStore.LockFile(openFile.Handle, (long)lockingRange.ByteOffset, (long)lockingRange.LengthInBytes, exclusiveLock);
                if (header.Status != NTStatus.STATUS_SUCCESS)
                {
                    state.LogToServer(Severity.Verbose, "Locking: Locking '{0}{1}' failed. Offset: {2}, Length: {3}. NTStatus: {4}.", share.Name, openFile.Path, lockingRange.ByteOffset, lockingRange.LengthInBytes, header.Status);
                    // [MS-CIFS] This client request is atomic. If the area to be locked is already locked or the
                    // lock request otherwise fails, no other ranges specified in the client request are locked.
                    for (int index = 0; index < lockIndex; index++)
                    {
                        share.FileStore.UnlockFile(openFile.Handle, (long)request.Locks[index].ByteOffset, (long)request.Locks[index].LengthInBytes);
                    }
                    return new ErrorResponse(request.CommandName);
                }
                state.LogToServer(Severity.Verbose, "Locking: Locking '{0}{1}' succeeded. Offset: {2}, Length: {3}.", share.Name, openFile.Path, lockingRange.ByteOffset, lockingRange.LengthInBytes);
            }

            return new LockingAndXResponse();
        }
    }
}