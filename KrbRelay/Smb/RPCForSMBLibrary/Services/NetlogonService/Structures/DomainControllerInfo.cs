/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.Services
{
    public class DomainControllerInfo
    {
        public string DomainControllerName;
        public string DomainControllerAddress;
        public uint DomainControllerAddressType;
        public Guid DomainGuid;
        public string DomainName;
        public string DnsForestName;
        public uint Flags;
        public string DcSiteName;
        public string ClientSiteName;

        public DomainControllerInfo()
        {
        }

        public DomainControllerInfo(NDRDomainControllerInfo info)
        {
            DomainControllerName = info.DomainControllerName.Value;
            DomainControllerAddress = info.DomainControllerAddress.Value;
            DomainControllerAddressType = info.DomainControllerAddressType;
            DomainGuid = info.DomainGuid;
            DomainName = info.DomainName.Value;
            DnsForestName = info.DnsForestName.Value;
            Flags = info.Flags;
            DcSiteName = info.DcSiteName.Value;
            ClientSiteName = info.ClientSiteName.Value;
        }
    }
}