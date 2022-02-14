/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB2;
using System;
using Utilities;

namespace SMBLibrary.Server.SMB2
{
    internal class TreeConnectHelper
    {
        internal static SMB2Command GetTreeConnectResponse(TreeConnectRequest request, SMB2ConnectionState state, NamedPipeShare services, SMBShareCollection shares)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            TreeConnectResponse response = new TreeConnectResponse();
            string shareName = ServerPathUtils.GetShareName(request.Path);
            ISMBShare share;
            ShareType shareType;
            ShareFlags shareFlags;
            if (String.Equals(shareName, NamedPipeShare.NamedPipeShareName, StringComparison.OrdinalIgnoreCase))
            {
                share = services;
                shareType = ShareType.Pipe;
                shareFlags = ShareFlags.NoCaching;
            }
            else
            {
                share = shares.GetShareFromName(shareName);
                if (share == null)
                {
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_OBJECT_PATH_NOT_FOUND);
                }

                shareType = ShareType.Disk;
                shareFlags = GetShareCachingFlags(((FileSystemShare)share).CachingPolicy);
                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, @"\"))
                {
                    state.LogToServer(Severity.Verbose, "Tree Connect to '{0}' failed. User '{1}' was denied access.", share.Name, session.UserName);
                    return new ErrorResponse(request.CommandName, NTStatus.STATUS_ACCESS_DENIED);
                }
            }

            uint? treeID = session.AddConnectedTree(share);
            if (!treeID.HasValue)
            {
                return new ErrorResponse(request.CommandName, NTStatus.STATUS_INSUFF_SERVER_RESOURCES);
            }
            state.LogToServer(Severity.Information, "Tree Connect: User '{0}' connected to '{1}' (SessionID: {2}, TreeID: {3})", session.UserName, share.Name, request.Header.SessionID, treeID.Value);
            response.Header.TreeID = treeID.Value;
            response.ShareType = shareType;
            response.ShareFlags = shareFlags;
            response.MaximalAccess = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA | FileAccessMask.FILE_APPEND_DATA |
                                                  FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                  FileAccessMask.FILE_EXECUTE |
                                                  FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                  AccessMask.DELETE | AccessMask.READ_CONTROL | AccessMask.WRITE_DAC | AccessMask.WRITE_OWNER | AccessMask.SYNCHRONIZE;
            return response;
        }

        private static ShareFlags GetShareCachingFlags(CachingPolicy cachingPolicy)
        {
            switch (cachingPolicy)
            {
                case CachingPolicy.ManualCaching:
                    return ShareFlags.ManualCaching;

                case CachingPolicy.AutoCaching:
                    return ShareFlags.AutoCaching;

                case CachingPolicy.VideoCaching:
                    return ShareFlags.VdoCaching;

                default:
                    return ShareFlags.NoCaching;
            }
        }

        internal static SMB2Command GetTreeDisconnectResponse(TreeDisconnectRequest request, ISMBShare share, SMB2ConnectionState state)
        {
            SMB2Session session = state.GetSession(request.Header.SessionID);
            session.DisconnectTree(request.Header.TreeID);
            state.LogToServer(Severity.Information, "Tree Disconnect: User '{0}' disconnected from '{1}' (SessionID: {2}, TreeID: {3})", session.UserName, share.Name, request.Header.SessionID, request.Header.TreeID);
            return new TreeDisconnectResponse();
        }
    }
}