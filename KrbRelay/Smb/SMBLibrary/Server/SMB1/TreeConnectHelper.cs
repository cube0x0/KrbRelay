/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using System;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class TreeConnectHelper
    {
        internal static SMB1Command GetTreeConnectResponse(SMB1Header header, TreeConnectAndXRequest request, SMB1ConnectionState state, NamedPipeShare services, SMBShareCollection shares)
        {
            SMB1Session session = state.GetSession(header.UID);
            bool isExtended = (request.Flags & TreeConnectFlags.ExtendedResponse) > 0;
            string shareName = ServerPathUtils.GetShareName(request.Path);
            ISMBShare share;
            ServiceName serviceName;
            OptionalSupportFlags supportFlags;
            if (String.Equals(shareName, NamedPipeShare.NamedPipeShareName, StringComparison.OrdinalIgnoreCase))
            {
                if (request.Service != ServiceName.AnyType && request.Service != ServiceName.NamedPipe)
                {
                    header.Status = NTStatus.STATUS_BAD_DEVICE_TYPE;
                    return new ErrorResponse(request.CommandName);
                }

                share = services;
                serviceName = ServiceName.NamedPipe;
                supportFlags = OptionalSupportFlags.SMB_SUPPORT_SEARCH_BITS | OptionalSupportFlags.SMB_CSC_NO_CACHING;
            }
            else
            {
                share = shares.GetShareFromName(shareName);
                if (share == null)
                {
                    header.Status = NTStatus.STATUS_OBJECT_PATH_NOT_FOUND;
                    return new ErrorResponse(request.CommandName);
                }

                if (request.Service != ServiceName.AnyType && request.Service != ServiceName.DiskShare)
                {
                    header.Status = NTStatus.STATUS_BAD_DEVICE_TYPE;
                    return new ErrorResponse(request.CommandName);
                }

                serviceName = ServiceName.DiskShare;
                supportFlags = OptionalSupportFlags.SMB_SUPPORT_SEARCH_BITS | GetCachingSupportFlags(((FileSystemShare)share).CachingPolicy);

                if (!((FileSystemShare)share).HasReadAccess(session.SecurityContext, @"\"))
                {
                    state.LogToServer(Severity.Verbose, "Tree Connect to '{0}' failed. User '{1}' was denied access.", share.Name, session.UserName);
                    header.Status = NTStatus.STATUS_ACCESS_DENIED;
                    return new ErrorResponse(request.CommandName);
                }
            }
            ushort? treeID = session.AddConnectedTree(share);
            if (!treeID.HasValue)
            {
                header.Status = NTStatus.STATUS_INSUFF_SERVER_RESOURCES;
                return new ErrorResponse(request.CommandName);
            }
            state.LogToServer(Severity.Information, "Tree Connect: User '{0}' connected to '{1}' (UID: {2}, TID: {3})", session.UserName, share.Name, header.UID, treeID.Value);
            header.TID = treeID.Value;
            if (isExtended)
            {
                return CreateTreeConnectResponseExtended(serviceName, supportFlags);
            }
            else
            {
                return CreateTreeConnectResponse(serviceName, supportFlags);
            }
        }

        private static OptionalSupportFlags GetCachingSupportFlags(CachingPolicy cachingPolicy)
        {
            switch (cachingPolicy)
            {
                case CachingPolicy.ManualCaching:
                    return OptionalSupportFlags.SMB_CSC_CACHE_MANUAL_REINT;

                case CachingPolicy.AutoCaching:
                    return OptionalSupportFlags.SMB_CSC_CACHE_AUTO_REINT;

                case CachingPolicy.VideoCaching:
                    return OptionalSupportFlags.SMB_CSC_CACHE_VDO;

                default:
                    return OptionalSupportFlags.SMB_CSC_NO_CACHING;
            }
        }

        private static TreeConnectAndXResponse CreateTreeConnectResponse(ServiceName serviceName, OptionalSupportFlags supportFlags)
        {
            TreeConnectAndXResponse response = new TreeConnectAndXResponse();
            response.OptionalSupport = supportFlags;
            response.NativeFileSystem = String.Empty;
            response.Service = serviceName;
            return response;
        }

        private static TreeConnectAndXResponseExtended CreateTreeConnectResponseExtended(ServiceName serviceName, OptionalSupportFlags supportFlags)
        {
            TreeConnectAndXResponseExtended response = new TreeConnectAndXResponseExtended();
            response.OptionalSupport = supportFlags;
            response.MaximalShareAccessRights = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA | FileAccessMask.FILE_APPEND_DATA |
                                                             FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                             FileAccessMask.FILE_EXECUTE |
                                                             FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                             AccessMask.DELETE | AccessMask.READ_CONTROL | AccessMask.WRITE_DAC | AccessMask.WRITE_OWNER | AccessMask.SYNCHRONIZE;
            response.GuestMaximalShareAccessRights = (AccessMask)(FileAccessMask.FILE_READ_DATA | FileAccessMask.FILE_WRITE_DATA |
                                                                  FileAccessMask.FILE_READ_EA | FileAccessMask.FILE_WRITE_EA |
                                                                  FileAccessMask.FILE_READ_ATTRIBUTES | FileAccessMask.FILE_WRITE_ATTRIBUTES) |
                                                                  AccessMask.READ_CONTROL | AccessMask.SYNCHRONIZE;
            response.NativeFileSystem = String.Empty;
            response.Service = serviceName;
            return response;
        }

        internal static SMB1Command GetTreeDisconnectResponse(SMB1Header header, TreeDisconnectRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            session.DisconnectTree(header.TID);
            state.LogToServer(Severity.Information, "Tree Disconnect: User '{0}' disconnected from '{1}' (UID: {2}, TID: {3})", session.UserName, share.Name, header.UID, header.TID);
            return new TreeDisconnectResponse();
        }
    }
}