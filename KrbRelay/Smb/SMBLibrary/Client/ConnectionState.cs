/* Copyright (C) 2017-2020 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NetBios;
using System.Net.Sockets;

namespace SMBLibrary.Client
{
    public class ConnectionState
    {
        private Socket m_clientSocket;
        private NBTConnectionReceiveBuffer m_receiveBuffer;

        public ConnectionState(Socket clientSocket)
        {
            m_clientSocket = clientSocket;
            m_receiveBuffer = new NBTConnectionReceiveBuffer();
        }

        public Socket ClientSocket
        {
            get
            {
                return m_clientSocket;
            }
        }

        public NBTConnectionReceiveBuffer ReceiveBuffer
        {
            get
            {
                return m_receiveBuffer;
            }
        }
    }
}