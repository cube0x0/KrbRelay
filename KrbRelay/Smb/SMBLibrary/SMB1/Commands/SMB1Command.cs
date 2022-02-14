/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.SMB1
{
    public abstract class SMB1Command
    {
        protected byte[] SMBParameters; // SMB_Parameters
        protected byte[] SMBData; // SMB_Data

        public SMB1Command()
        {
            SMBParameters = new byte[0];
            SMBData = new byte[0];
        }

        public SMB1Command(byte[] buffer, int offset, bool isUnicode)
        {
            byte wordCount = ByteReader.ReadByte(buffer, ref offset);
            if (CommandName == CommandName.SMB_COM_NT_CREATE_ANDX && wordCount == NTCreateAndXResponseExtended.DeclaredParametersLength / 2)
            {
                // [MS-SMB] Section 2.2.4.9.2 and Note <49>:
                // Windows-based SMB servers send 50 (0x32) words in the extended response although they set the WordCount field to 0x2A.
                wordCount = NTCreateAndXResponseExtended.ParametersLength / 2;
            }
            SMBParameters = ByteReader.ReadBytes(buffer, ref offset, wordCount * 2);
            ushort byteCount = LittleEndianReader.ReadUInt16(buffer, ref offset);
            SMBData = ByteReader.ReadBytes(buffer, ref offset, byteCount);
        }

        public abstract CommandName CommandName
        {
            get;
        }

        public virtual byte[] GetBytes(bool isUnicode)
        {
            if (SMBParameters.Length % 2 > 0)
            {
                throw new Exception("SMB_Parameters Length must be a multiple of 2");
            }
            int length = 1 + SMBParameters.Length + 2 + SMBData.Length;
            byte[] buffer = new byte[length];
            byte wordCount = (byte)(SMBParameters.Length / 2);
            if (this is NTCreateAndXResponseExtended)
            {
                // [MS-SMB] Section 2.2.4.9.2 and Note <49>:
                // Windows-based SMB servers send 50 (0x32) words in the extended response although they set the WordCount field to 0x2A.
                // WordCount SHOULD be set to 0x2A.
                wordCount = NTCreateAndXResponseExtended.DeclaredParametersLength / 2;
            }
            ushort byteCount = (ushort)SMBData.Length;

            int offset = 0;
            ByteWriter.WriteByte(buffer, ref offset, wordCount);
            ByteWriter.WriteBytes(buffer, ref offset, SMBParameters);
            LittleEndianWriter.WriteUInt16(buffer, ref offset, byteCount);
            ByteWriter.WriteBytes(buffer, ref offset, SMBData);

            return buffer;
        }

        public static SMB1Command ReadCommand(byte[] buffer, int offset, CommandName commandName, SMB1Header header)
        {
            if ((header.Flags & HeaderFlags.Reply) > 0)
            {
                return ReadCommandResponse(buffer, offset, commandName, header.UnicodeFlag);
            }
            else
            {
                return ReadCommandRequest(buffer, offset, commandName, header.UnicodeFlag);
            }
        }

        public static SMB1Command ReadCommandRequest(byte[] buffer, int offset, CommandName commandName, bool isUnicode)
        {
            switch (commandName)
            {
                case CommandName.SMB_COM_CREATE_DIRECTORY:
                    return new CreateDirectoryRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_DELETE_DIRECTORY:
                    return new DeleteDirectoryRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_CLOSE:
                    return new CloseRequest(buffer, offset);

                case CommandName.SMB_COM_FLUSH:
                    return new FlushRequest(buffer, offset);

                case CommandName.SMB_COM_DELETE:
                    return new DeleteRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_RENAME:
                    return new RenameRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_QUERY_INFORMATION:
                    return new QueryInformationRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_SET_INFORMATION:
                    return new SetInformationRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_READ:
                    return new ReadRequest(buffer, offset);

                case CommandName.SMB_COM_WRITE:
                    return new WriteRequest(buffer, offset);

                case CommandName.SMB_COM_CHECK_DIRECTORY:
                    return new CheckDirectoryRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_WRITE_RAW:
                    return new WriteRawRequest(buffer, offset);

                case CommandName.SMB_COM_SET_INFORMATION2:
                    return new SetInformation2Request(buffer, offset);

                case CommandName.SMB_COM_LOCKING_ANDX:
                    return new LockingAndXRequest(buffer, offset);

                case CommandName.SMB_COM_TRANSACTION:
                    return new TransactionRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_TRANSACTION_SECONDARY:
                    return new TransactionSecondaryRequest(buffer, offset);

                case CommandName.SMB_COM_ECHO:
                    return new EchoRequest(buffer, offset);

                case CommandName.SMB_COM_OPEN_ANDX:
                    return new OpenAndXRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_READ_ANDX:
                    return new ReadAndXRequest(buffer, offset);

                case CommandName.SMB_COM_WRITE_ANDX:
                    return new WriteAndXRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_TRANSACTION2:
                    return new Transaction2Request(buffer, offset, isUnicode);

                case CommandName.SMB_COM_TRANSACTION2_SECONDARY:
                    return new Transaction2SecondaryRequest(buffer, offset);

                case CommandName.SMB_COM_FIND_CLOSE2:
                    return new FindClose2Request(buffer, offset);

                case CommandName.SMB_COM_TREE_DISCONNECT:
                    return new TreeDisconnectRequest(buffer, offset);

                case CommandName.SMB_COM_NEGOTIATE:
                    return new NegotiateRequest(buffer, offset);

                case CommandName.SMB_COM_SESSION_SETUP_ANDX:
                    {
                        byte wordCount = ByteReader.ReadByte(buffer, offset);
                        if (wordCount * 2 == SessionSetupAndXRequest.ParametersLength)
                        {
                            return new SessionSetupAndXRequest(buffer, offset, isUnicode);
                        }
                        else if (wordCount * 2 == SessionSetupAndXRequestExtended.ParametersLength)
                        {
                            return new SessionSetupAndXRequestExtended(buffer, offset, isUnicode);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_LOGOFF_ANDX:
                    return new LogoffAndXRequest(buffer, offset);

                case CommandName.SMB_COM_TREE_CONNECT_ANDX:
                    return new TreeConnectAndXRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_NT_TRANSACT:
                    return new NTTransactRequest(buffer, offset);

                case CommandName.SMB_COM_NT_TRANSACT_SECONDARY:
                    return new NTTransactSecondaryRequest(buffer, offset);

                case CommandName.SMB_COM_NT_CREATE_ANDX:
                    return new NTCreateAndXRequest(buffer, offset, isUnicode);

                case CommandName.SMB_COM_NT_CANCEL:
                    return new NTCancelRequest(buffer, offset);

                default:
                    throw new InvalidDataException("Invalid SMB command 0x" + ((byte)commandName).ToString("X2"));
            }
        }

        public static SMB1Command ReadCommandResponse(byte[] buffer, int offset, CommandName commandName, bool isUnicode)
        {
            byte wordCount = ByteReader.ReadByte(buffer, offset);
            switch (commandName)
            {
                case CommandName.SMB_COM_CREATE_DIRECTORY:
                    return new CreateDirectoryResponse(buffer, offset);

                case CommandName.SMB_COM_DELETE_DIRECTORY:
                    return new DeleteDirectoryResponse(buffer, offset);

                case CommandName.SMB_COM_CLOSE:
                    return new CloseResponse(buffer, offset);

                case CommandName.SMB_COM_FLUSH:
                    return new FlushResponse(buffer, offset);

                case CommandName.SMB_COM_DELETE:
                    return new DeleteResponse(buffer, offset);

                case CommandName.SMB_COM_RENAME:
                    return new RenameResponse(buffer, offset);

                case CommandName.SMB_COM_QUERY_INFORMATION:
                    {
                        if (wordCount * 2 == QueryInformationResponse.ParameterLength)
                        {
                            return new QueryInformationResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_SET_INFORMATION:
                    return new SetInformationResponse(buffer, offset);

                case CommandName.SMB_COM_READ:
                    {
                        if (wordCount * 2 == ReadResponse.ParametersLength)
                        {
                            return new ReadResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_WRITE:
                    {
                        if (wordCount * 2 == WriteResponse.ParametersLength)
                        {
                            return new WriteResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_CHECK_DIRECTORY:
                    return new CheckDirectoryResponse(buffer, offset);

                case CommandName.SMB_COM_WRITE_RAW:
                    {
                        if (wordCount * 2 == WriteRawInterimResponse.ParametersLength)
                        {
                            return new WriteRawInterimResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_WRITE_COMPLETE:
                    {
                        if (wordCount * 2 == WriteRawFinalResponse.ParametersLength)
                        {
                            return new WriteRawFinalResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_SET_INFORMATION2:
                    return new SetInformation2Response(buffer, offset);

                case CommandName.SMB_COM_LOCKING_ANDX:
                    {
                        if (wordCount * 2 == LockingAndXResponse.ParametersLength)
                        {
                            return new LockingAndXResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_TRANSACTION:
                    {
                        if (wordCount * 2 == TransactionInterimResponse.ParametersLength)
                        {
                            return new TransactionInterimResponse(buffer, offset);
                        }
                        else
                        {
                            return new TransactionResponse(buffer, offset);
                        }
                    }
                case CommandName.SMB_COM_ECHO:
                    {
                        if (wordCount * 2 == EchoResponse.ParametersLength)
                        {
                            return new EchoResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_OPEN_ANDX:
                    {
                        if (wordCount * 2 == OpenAndXResponse.ParametersLength)
                        {
                            return new OpenAndXResponse(buffer, offset);
                        }
                        else if (wordCount * 2 == OpenAndXResponseExtended.ParametersLength)
                        {
                            return new OpenAndXResponseExtended(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_READ_ANDX:
                    {
                        if (wordCount * 2 == ReadAndXResponse.ParametersLength)
                        {
                            return new ReadAndXResponse(buffer, offset, isUnicode);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_WRITE_ANDX:
                    {
                        if (wordCount * 2 == WriteAndXResponse.ParametersLength)
                        {
                            return new WriteAndXResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_TRANSACTION2:
                    {
                        if (wordCount * 2 == Transaction2InterimResponse.ParametersLength)
                        {
                            return new Transaction2InterimResponse(buffer, offset);
                        }
                        else
                        {
                            return new Transaction2Response(buffer, offset);
                        }
                    }
                case CommandName.SMB_COM_FIND_CLOSE2:
                    return new FindClose2Response(buffer, offset);

                case CommandName.SMB_COM_TREE_DISCONNECT:
                    return new TreeDisconnectResponse(buffer, offset);

                case CommandName.SMB_COM_NEGOTIATE:
                    {
                        // Both NegotiateResponse and NegotiateResponseExtended have WordCount set to 17
                        if (wordCount * 2 == NegotiateResponse.ParametersLength)
                        {
                            Capabilities capabilities = (Capabilities)LittleEndianConverter.ToUInt32(buffer, offset + 20);
                            if ((capabilities & Capabilities.ExtendedSecurity) > 0)
                            {
                                return new NegotiateResponseExtended(buffer, offset);
                            }
                            else
                            {
                                return new NegotiateResponse(buffer, offset, isUnicode);
                            }
                        }
                        if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_SESSION_SETUP_ANDX:
                    {
                        if (wordCount * 2 == SessionSetupAndXResponse.ParametersLength)
                        {
                            return new SessionSetupAndXResponse(buffer, offset, isUnicode);
                        }
                        else if (wordCount * 2 == SessionSetupAndXResponseExtended.ParametersLength)
                        {
                            return new SessionSetupAndXResponseExtended(buffer, offset, isUnicode);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_LOGOFF_ANDX:
                    {
                        if (wordCount * 2 == LogoffAndXResponse.ParametersLength)
                        {
                            return new LogoffAndXResponse(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_TREE_CONNECT_ANDX:
                    {
                        if (wordCount * 2 == TreeConnectAndXResponse.ParametersLength)
                        {
                            return new TreeConnectAndXResponse(buffer, offset, isUnicode);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                case CommandName.SMB_COM_NT_TRANSACT:
                    {
                        if (wordCount * 2 == NTTransactInterimResponse.ParametersLength)
                        {
                            return new NTTransactInterimResponse(buffer, offset);
                        }
                        else
                        {
                            return new NTTransactResponse(buffer, offset);
                        }
                    }
                case CommandName.SMB_COM_NT_CREATE_ANDX:
                    {
                        if (wordCount * 2 == NTCreateAndXResponse.ParametersLength)
                        {
                            return new NTCreateAndXResponse(buffer, offset);
                        }
                        else if (wordCount * 2 == NTCreateAndXResponseExtended.ParametersLength ||
                                 wordCount * 2 == NTCreateAndXResponseExtended.DeclaredParametersLength)
                        {
                            return new NTCreateAndXResponseExtended(buffer, offset);
                        }
                        else if (wordCount == 0)
                        {
                            return new ErrorResponse(commandName);
                        }
                        else
                        {
                            throw new InvalidDataException();
                        }
                    }
                default:
                    throw new InvalidDataException("Invalid SMB command 0x" + ((byte)commandName).ToString("X2"));
            }
        }

        public static implicit operator List<SMB1Command>(SMB1Command command)
        {
            List<SMB1Command> result = new List<SMB1Command>();
            result.Add(command);
            return result;
        }
    }
}