/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class TransactionSubcommand
    {
        public TransactionSubcommand()
        {
        }

        public virtual byte[] GetSetup()
        {
            return new byte[0];
        }

        public virtual byte[] GetParameters()
        {
            return new byte[0];
        }

        public virtual byte[] GetData(bool isUnicode)
        {
            return new byte[0];
        }

        public abstract TransactionSubcommandName SubcommandName
        {
            get;
        }

        public static TransactionSubcommand GetSubcommandRequest(byte[] setup, byte[] parameters, byte[] data, bool isUnicode)
        {
            if (setup.Length == 4)
            {
                TransactionSubcommandName subcommandName = (TransactionSubcommandName)LittleEndianConverter.ToUInt16(setup, 0);
                switch (subcommandName)
                {
                    case TransactionSubcommandName.TRANS_SET_NMPIPE_STATE:
                        return new TransactionSetNamedPipeStateRequest(setup, parameters);

                    case TransactionSubcommandName.TRANS_RAW_READ_NMPIPE:
                        return new TransactionRawReadNamedPipeRequest(setup);

                    case TransactionSubcommandName.TRANS_QUERY_NMPIPE_STATE:
                        return new TransactionQueryNamedPipeStateRequest(setup, parameters);

                    case TransactionSubcommandName.TRANS_QUERY_NMPIPE_INFO:
                        return new TransactionQueryNamedPipeInfoRequest(setup, parameters);

                    case TransactionSubcommandName.TRANS_PEEK_NMPIPE:
                        return new TransactionPeekNamedPipeRequest(setup);

                    case TransactionSubcommandName.TRANS_TRANSACT_NMPIPE:
                        return new TransactionTransactNamedPipeRequest(setup, data);

                    case TransactionSubcommandName.TRANS_RAW_WRITE_NMPIPE:
                        return new TransactionRawWriteNamedPipeRequest(setup, data);

                    case TransactionSubcommandName.TRANS_READ_NMPIPE:
                        return new TransactionReadNamedPipeRequest(setup);

                    case TransactionSubcommandName.TRANS_WRITE_NMPIPE:
                        return new TransactionWriteNamedPipeRequest(setup, data);

                    case TransactionSubcommandName.TRANS_WAIT_NMPIPE:
                        return new TransactionWaitNamedPipeRequest(setup);

                    case TransactionSubcommandName.TRANS_CALL_NMPIPE:
                        return new TransactionCallNamedPipeRequest(setup, data);
                }
            }
            throw new InvalidDataException();
        }
    }
}