/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.SMB1
{
    public class ServiceNameHelper
    {
        public static string GetServiceString(ServiceName serviceName)
        {
            switch (serviceName)
            {
                case ServiceName.DiskShare:
                    return "A:";

                case ServiceName.PrinterShare:
                    return "LPT1:";

                case ServiceName.NamedPipe:
                    return "IPC";

                case ServiceName.SerialCommunicationsDevice:
                    return "COMM";

                default:
                    return "?????";
            }
        }

        public static ServiceName GetServiceName(string serviceString)
        {
            switch (serviceString)
            {
                case "A:":
                    return ServiceName.DiskShare;

                case "LPT1:":
                    return ServiceName.PrinterShare;

                case "IPC":
                    return ServiceName.NamedPipe;

                case "COMM":
                    return ServiceName.SerialCommunicationsDevice;

                default:
                    return ServiceName.AnyType;
            }
        }
    }
}