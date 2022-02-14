/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;

namespace SMBLibrary.Services
{
    /// <summary>
    /// [MS-NRPC]
    /// </summary>
    public class NetlogonService : RemoteService
    {
        public const string ServicePipeName = @"netlogon";
        public static readonly Guid ServiceInterfaceGuid = new Guid("12345678-1234-ABCD-EF00-01234567CFFB");
        public const int ServiceVersion = 1;

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

        public override byte[] GetResponseBytes(ushort opNum, byte[] requestBytes)
        {
            throw new NotImplementedException();
        }
    }
}