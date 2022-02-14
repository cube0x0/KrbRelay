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
    /// [MS-LSAT] and [MS-LSAD]
    /// </summary>
    public class LsaRemoteService : RemoteService
    {
        public const string ServicePipeName = @"lsarpc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("12345778-1234-ABCD-EF00-0123456789AB");
        public const int ServiceVersion = 0;

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