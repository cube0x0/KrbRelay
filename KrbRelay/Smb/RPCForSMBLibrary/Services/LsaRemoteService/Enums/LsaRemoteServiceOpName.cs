/* Copyright (C) 2021 Vincent LE TOUX <vincent.letoux@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.Services
{
    public enum LsaRemoteServiceOpName : ushort
    {
        LsarClose = 0,
        LsarOpenPolicy = 6,
        LsarLookupNames = 14,
        LsarLookupSids = 15,
        AddAccountRights = 37
    }
}