/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

namespace SMBLibrary.Server
{
    internal class ProcessStateObject
    {
        public ushort SubcommandID;
        public uint MaxParameterCount; // The maximum number of Trans_Parameters bytes that the client accepts in the transaction response
        public uint MaxDataCount;      // The maximum number of Trans_Data bytes that the client accepts in the transaction response
        public uint Timeout;
        public string Name; // The pathname of the [..] named pipe to which the transaction subcommand applies, or a client-supplied [..] name for the transaction.
        public byte[] TransactionSetup;
        public byte[] TransactionParameters;
        public byte[] TransactionData;
        public int TransactionParametersReceived; // length in bytes
        public int TransactionDataReceived; // length in bytes
    }
}