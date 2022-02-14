/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.Authentication.GSSAPI;
using System.Net;

namespace SMBLibrary
{
    public class SecurityContext
    {
        private string m_userName;
        private string m_machineName;
        private IPEndPoint m_clientEndPoint;
        public GSSContext AuthenticationContext;
        public object AccessToken;

        public SecurityContext(string userName, string machineName, IPEndPoint clientEndPoint, GSSContext authenticationContext, object accessToken)
        {
            m_userName = userName;
            m_machineName = machineName;
            m_clientEndPoint = clientEndPoint;
            AuthenticationContext = authenticationContext;
            AccessToken = accessToken;
        }

        public string UserName
        {
            get
            {
                return m_userName;
            }
        }

        public string MachineName
        {
            get
            {
                return m_machineName;
            }
        }

        public IPEndPoint ClientEndPoint
        {
            get
            {
                return m_clientEndPoint;
            }
        }
    }
}