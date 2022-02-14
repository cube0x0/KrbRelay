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
    /// [MS-EFSR]
    /// </summary>
    public class EFSService : RemoteService
    {
        public const string ServicePipeName = @"lsarpc";
        public static readonly Guid ServiceInterfaceGuid = new Guid("c681d488-d850-11d0-8c52-00c04fd90f7e");
        public const int ServiceVersion = 1;
        // also df1941c5-fe89-4e79-bf10-463657acf44d with efsrpc

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