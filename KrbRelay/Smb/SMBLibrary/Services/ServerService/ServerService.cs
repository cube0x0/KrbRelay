/* Copyright (C) 2014-2018 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-SRVS]
    /// </summary>
    public class ServerService : RemoteService
    {
        public const string ServicePipeName = @"srvsvc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("4B324FC8-1670-01D3-1278-5A47BF6EE188");
        public const int ServiceVersion = 3;

        public const int MaxPreferredLength = -1; // MAX_PREFERRED_LENGTH

        private PlatformName m_platformID;
        private string m_serverName;
        private uint m_verMajor;
        private uint m_verMinor;
        private ServerType m_serverType;

        private List<string> m_shares;

        public ServerService(string serverName, List<string> shares)
        {
            m_platformID = PlatformName.NT;
            m_serverName = serverName;
            m_verMajor = 5;
            m_verMinor = 2;
            m_serverType = ServerType.Workstation | ServerType.Server | ServerType.WindowsNT | ServerType.ServerNT | ServerType.MasterBrowser;

            m_shares = shares;
        }

        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes)
        {
            switch ((ServerServiceOpName)opNum)
            {
                case ServerServiceOpName.NetrShareEnum:
                    {
                        NetrShareEnumRequest request = new NetrShareEnumRequest(requestBytes);
                        NetrShareEnumResponse response = GetNetrShareEnumResponse(request);
                        return response.GetBytes();
                    }
                case ServerServiceOpName.NetrShareGetInfo:
                    {
                        NetrShareGetInfoRequest request = new NetrShareGetInfoRequest(requestBytes);
                        NetrShareGetInfoResponse response = GetNetrShareGetInfoResponse(request);
                        return response.GetBytes();
                    }
                case ServerServiceOpName.NetrServerGetInfo:
                    {
                        NetrServerGetInfoRequest request = new NetrServerGetInfoRequest(requestBytes);
                        NetrServerGetInfoResponse response = GetNetrWkstaGetInfoResponse(request);
                        return response.GetBytes();
                    }
                default:
                    throw new UnsupportedOpNumException();
            }
        }

        public NetrShareEnumResponse GetNetrShareEnumResponse(NetrShareEnumRequest request)
        {
            NetrShareEnumResponse response = new NetrShareEnumResponse();
            switch (request.InfoStruct.Level)
            {
                case 0:
                    {
                        // We ignore request.PreferedMaximumLength
                        ShareInfo0Container info = new ShareInfo0Container();
                        foreach (string shareName in m_shares)
                        {
                            info.Add(new ShareInfo0Entry(shareName));
                        }
                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)m_shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 1:
                    {
                        // We ignore request.PreferedMaximumLength
                        ShareInfo1Container info = new ShareInfo1Container();
                        foreach (string shareName in m_shares)
                        {
                            info.Add(new ShareInfo1Entry(shareName, new ShareTypeExtended(ShareType.DiskDrive)));
                        }
                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)m_shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 2:
                    {
                        // We ignore request.PreferedMaximumLength
                        ShareInfo2Container info = new ShareInfo2Container();
                        foreach (string shareName in m_shares)
                        {
                            info.Add(new ShareInfo2Entry(shareName, new ShareTypeExtended(ShareType.DiskDrive)));
                        }
                        response.InfoStruct = new ShareEnum(info);
                        response.TotalEntries = (uint)m_shares.Count;
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 501:
                case 502:
                case 503:
                    {
                        response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                        response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                        return response;
                    }
                default:
                    {
                        response.InfoStruct = new ShareEnum(request.InfoStruct.Level);
                        response.Result = Win32Error.ERROR_INVALID_LEVEL;
                        return response;
                    }
            }
        }

        public NetrShareGetInfoResponse GetNetrShareGetInfoResponse(NetrShareGetInfoRequest request)
        {
            int shareIndex = IndexOfShare(request.NetName);

            NetrShareGetInfoResponse response = new NetrShareGetInfoResponse();
            if (shareIndex == -1)
            {
                response.InfoStruct = new ShareInfo(request.Level);
                response.Result = Win32Error.NERR_NetNameNotFound;
                return response;
            }

            switch (request.Level)
            {
                case 0:
                    {
                        ShareInfo0Entry info = new ShareInfo0Entry(m_shares[shareIndex]);
                        response.InfoStruct = new ShareInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 1:
                    {
                        ShareInfo1Entry info = new ShareInfo1Entry(m_shares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive));
                        response.InfoStruct = new ShareInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 2:
                    {
                        ShareInfo2Entry info = new ShareInfo2Entry(m_shares[shareIndex], new ShareTypeExtended(ShareType.DiskDrive));
                        response.InfoStruct = new ShareInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 501:
                case 502:
                case 503:
                case 1005:
                    {
                        response.InfoStruct = new ShareInfo(request.Level);
                        response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                        return response;
                    }
                default:
                    {
                        response.InfoStruct = new ShareInfo(request.Level);
                        response.Result = Win32Error.ERROR_INVALID_LEVEL;
                        return response;
                    }
            }
        }

        public NetrServerGetInfoResponse GetNetrWkstaGetInfoResponse(NetrServerGetInfoRequest request)
        {
            NetrServerGetInfoResponse response = new NetrServerGetInfoResponse();
            switch (request.Level)
            {
                case 100:
                    {
                        ServerInfo100 info = new ServerInfo100();
                        info.PlatformID = m_platformID;
                        info.ServerName.Value = m_serverName;
                        response.InfoStruct = new ServerInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 101:
                    {
                        ServerInfo101 info = new ServerInfo101();
                        info.PlatformID = m_platformID;
                        info.ServerName.Value = m_serverName;
                        info.VerMajor = m_verMajor;
                        info.VerMinor = m_verMinor;
                        info.Type = m_serverType;
                        info.Comment.Value = String.Empty;
                        response.InfoStruct = new ServerInfo(info);
                        response.Result = Win32Error.ERROR_SUCCESS;
                        return response;
                    }
                case 102:
                case 103:
                case 502:
                case 503:
                    {
                        response.InfoStruct = new ServerInfo(request.Level);
                        response.Result = Win32Error.ERROR_NOT_SUPPORTED;
                        return response;
                    }
                default:
                    {
                        response.InfoStruct = new ServerInfo(request.Level);
                        response.Result = Win32Error.ERROR_INVALID_LEVEL;
                        return response;
                    }
            }
        }

        private int IndexOfShare(string shareName)
        {
            for (int index = 0; index < m_shares.Count; index++)
            {
                if (m_shares[index].Equals(shareName, StringComparison.OrdinalIgnoreCase))
                {
                    return index;
                }
            }

            return -1;
        }

        public override Guid InterfaceGuid
        {
            get
            {
                return ServiceInterfaceGuid;
            }
        }

        public override string PipeName
        {
            get
            {
                return ServicePipeName;
            }
        }
    }
}