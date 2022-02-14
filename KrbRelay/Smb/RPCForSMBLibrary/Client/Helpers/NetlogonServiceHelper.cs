/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Client.Helpers;
using SMBLibrary.Services;

namespace SMBLibrary.Client
{
    public class NetlogonServiceHelper
    {
        public static DomainControllerInfo DsGetDCNames(ISMBClient client, string ServerName, string DomainName, string SiteName, uint Flags, out NTStatus status)
        {
            using (RPCCallHelper rpc = new RPCCallHelper(client, NetlogonService.ServicePipeName, NetlogonService.ServiceInterfaceGuid, NetlogonService.ServiceVersion))
            {
                status = rpc.BindPipe();
                if (status != NTStatus.STATUS_SUCCESS)
                    return null;

                DsrGetDcNameRequest getDcNameRequest = new DsrGetDcNameRequest();
                getDcNameRequest.ServerName = ServerName;
                getDcNameRequest.DomainName = DomainName;
                getDcNameRequest.SiteName = SiteName;
                getDcNameRequest.Flags = Flags;

                DsrGetDcNameResponse getDcNameResponse;

                status = rpc.ExecuteCall((ushort)NetlogonServiceOpName.DsrGetDcName, getDcNameRequest, out getDcNameResponse);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return null;
                }
                return new DomainControllerInfo(getDcNameResponse.DCInfo);
            }
        }
    }
}