/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class LockHelper
    {
        internal static SMB2Command GetLockResponse(LockRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            OpenFileObject openFile = session.GetOpenFileObject(request.FileId);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "Lock failed. Invalid FileId. (SessionID: {0}, TreeID: {1}, FileId: {2})", request.Header.SessionID, request.Header.TreeID, request.FileId.Volatile);
                return new ErrorResponse(request.CommandName, NTStatus.STATUS_FILE_CLOSED);
            }

            if (request.Locks.Count == 0)
            {
                // [MS-SMB2] The lock count MUST be greater than or equal to 1
                state.LogToServer(Severity.Verbose, "Lock: Invalid number of locks, must be greater than 0.");
                return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
            }

            // [MS-SMB2] If the flags of the initial SMB2_LOCK_ELEMENT in the Locks array of the request has
            // SMB2_LOCKFLAG_UNLOCK set, the server MUST process the lock array as a series of unlocks.
            // Otherwise, it MUST process the lock array as a series of lock requests.
            bool unlock = request.Locks[0].Unlock;
            foreach (LockElement lockElement in request.Locks)
            {
                if (unlock)
                {
                    if (lockElement.SharedLock || lockElement.ExclusiveLock)
                    {
                        state.LogToServer(Severity.Verbose, "Lock: Invalid parameter: Lock in a series of unlocks.");
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                    }
                }
                else
                {
                    if (lockElement.Unlock)
                    {
                        state.LogToServer(Severity.Verbose, "Lock: Invalid parameter: Unlock in a series of locks.");
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                    }

                    if (lockElement.SharedLock && lockElement.ExclusiveLock)
                    {
                        state.LogToServer(Severity.Verbose, "Lock: Invalid parameter: SMB2_LOCKFLAG_SHARED_LOCK and SMB2_LOCKFLAG_EXCLUSIVE_LOCK are mutually exclusive.");
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                    }

                    if (request.Locks.Count > 1 && !lockElement.FailImmediately)
                    {
                        state.LogToServer(Severity.Verbose, "Lock: Invalid parameter: SMB2_LOCKFLAG_FAIL_IMMEDIATELY not set in a series of locks.");
                        return new ErrorResponse(request.CommandName, NTStatus.STATUS_INVALID_PARAMETER);
                    }
                }
            }

            for (int lockIndex = 0; lockIndex < request.Locks.Count; lockIndex++)
            {
                LockElement lockElement = request.Locks[lockIndex];
                if (unlock)
                {
                    NTStatus status = share.FileStore.UnlockFile(openFile.Handle, (long)lockElement.Offset, (long)lockElement.Length);
                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        // [MS-SMB2] If the unlock operation fails, the server MUST fail the operation with the error code received from the object store and stop processing further entries in the Locks array.
                        state.LogToServer(Severity.Information, "Lock: Unlocking '{0}{1}' failed. Offset: {2}, Length: {3}. NTStatus: {4}.", share.Name, openFile.Path, lockElement.Offset, lockElement.Length, status);
                        return new ErrorResponse(request.CommandName, status);
                    }
                    state.LogToServer(Severity.Information, "Lock: Unlocking '{0}{1}' succeeded. Offset: {2}, Length: {3}.", share.Name, openFile.Path, lockElement.Offset, lockElement.Length);
                }
                else
                {
                    NTStatus status = share.FileStore.LockFile(openFile.Handle, (long)lockElement.Offset, (long)lockElement.Length, lockElement.ExclusiveLock);
                    if (status != NTStatus.STATUS_SUCCESS)
                    {
                        // [MS-SMB2] If the lock operation fails, the server MUST unlock any ranges locked as part of processing the previous entries in the Locks array of this request.
                        state.LogToServer(Severity.Information, "Lock: Locking '{0}{1}' failed. Offset: {2}, Length: {3}. NTStatus: {4}.", share.Name, openFile.Path, lockElement.Offset, lockElement.Length, status);
                        for (int index = 0; index < lockIndex; index++)
                        {
                            share.FileStore.UnlockFile(openFile.Handle, (long)request.Locks[index].Offset, (long)request.Locks[index].Length);
                        }
                        return new ErrorResponse(request.CommandName, status);
                    }
                    state.LogToServer(Severity.Information, "Lock: Locking '{0}{1}' succeeded. Offset: {2}, Length: {3}.", share.Name, openFile.Path, lockElement.Offset, lockElement.Length);
                }
            }

            return new LockResponse();
        }
    }
}