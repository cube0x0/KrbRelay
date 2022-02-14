/* Copyright (C) 2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Net;

namespace SMBLibrary.Server
{
    public class ConnectionRequestEventArgs : EventArgs
    {
        public IPEndPoint IPEndPoint;
        public bool Accept = true;

        public ConnectionRequestEventArgs(IPEndPoint ipEndPoint)
        {
            IPEndPoint = ipEndPoint;
        }
    }
}