/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;
using System;

namespace SMBLibrary.Client
{
    public class ServerServiceHelperEx
    {
        public static DateTime NetrRemoteTOD(ISMBClient client, string ServerName, out NTStatus status)
        {
            using (RPCCallHelper rpc = new RPCCallHelper(client, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion))
            {
                status = rpc.BindPipe();
                if (status != NTStatus.STATUS_SUCCESS)
                    return DateTime.MinValue;

                NetrRemoteTODRequest netrRemoteTODRequest = new NetrRemoteTODRequest();
                netrRemoteTODRequest.ServerName = ServerName;

                NetrRemoteTODResponse netrRemoteTODResponse;

                status = rpc.ExecuteCall((ushort)ServerServiceOpName.NetrRemoteTOD, netrRemoteTODRequest, out netrRemoteTODResponse);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return DateTime.MinValue;
                }

                return netrRemoteTODResponse.TimeOfDayInfo.ToDateTime();
            }
        }

        public static NetrServerStatisticsGetResponse NetrServerStatisticsGet(ISMBClient client, string serverName, string service, uint level, uint options, out NTStatus status)
        {
            using (RPCCallHelper rpc = new RPCCallHelper(client, ServerService.ServicePipeName, ServerService.ServiceInterfaceGuid, ServerService.ServiceVersion))
            {
                status = rpc.BindPipe();
                if (status != NTStatus.STATUS_SUCCESS)
                    return null;

                NetrServerStatisticsGetRequest netrServerStatisticsGetRequest = new NetrServerStatisticsGetRequest();
                netrServerStatisticsGetRequest.ServerName = serverName;
                netrServerStatisticsGetRequest.Service = service;
                netrServerStatisticsGetRequest.Level = level;
                netrServerStatisticsGetRequest.Options = options;

                NetrServerStatisticsGetResponse netrServerStatisticsGetResponse;

                status = rpc.ExecuteCall((ushort)ServerServiceOpName.NetrServerStatisticsGet, netrServerStatisticsGetRequest, out netrServerStatisticsGetResponse);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }

                return netrServerStatisticsGetResponse;
            }
        }
    }
}