/* Copyright (C) 2014-2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.NetBios;
using SMBLibrary.Server.SMB1;
using SMBLibrary.SMB1;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.Server
{
    public partial class SMBServer
    {
        private void ProcessSMB1Message(SMB1Message message, ref ConnectionState state)
        {
            SMB1Header header = new SMB1Header();
            PrepareResponseHeader(header, message.Header);
            List<SMB1Command> responses = new List<SMB1Command>();

            bool isBatchedRequest = (message.Commands.Count > 1);
            foreach (SMB1Command command in message.Commands)
            {
                List<SMB1Command> commandResponses = ProcessSMB1Command(header, command, ref state);
                responses.AddRange(commandResponses);

                if (header.Status != NTStatus.STATUS_SUCCESS)
                {
                    break;
                }
            }

            if (isBatchedRequest)
            {
                if (responses.Count > 0)
                {
                    // The server MUST batch the response into an AndX Response chain.
                    SMB1Message reply = new SMB1Message();
                    reply.Header = header;
                    for (int index = 0; index < responses.Count; index++)
                    {
                        if (reply.Commands.Count == 0 ||
                            reply.Commands[reply.Commands.Count - 1] is SMBAndXCommand)
                        {
                            reply.Commands.Add(responses[index]);
                            responses.RemoveAt(index);
                            index--;
                        }
                        else
                        {
                            break;
                        }
                    }
                    EnqueueMessage(state, reply);
                }
            }

            foreach (SMB1Command response in responses)
            {
                SMB1Message reply = new SMB1Message();
                reply.Header = header;
                reply.Commands.Add(response);
                EnqueueMessage(state, reply);
            }
        }

        /// <summary>
        /// May return an empty list
        /// </summary>
        private List<SMB1Command> ProcessSMB1Command(SMB1Header header, SMB1Command command, ref ConnectionState state)
        {
            if (state.Dialect == SMBDialect.NotSet)
            {
                if (command is NegotiateRequest)
                {
                    NegotiateRequest request = (NegotiateRequest)command;
                    if (request.Dialects.Contains(SMBServer.NTLanManagerDialect))
                    {
                        state = new SMB1ConnectionState(state);
                        state.Dialect = SMBDialect.NTLM012;
                        m_connectionManager.AddConnection(state);
                        if (EnableExtendedSecurity && header.ExtendedSecurityFlag)
                        {
                            return NegotiateHelper.GetNegotiateResponseExtended(request, m_serverGuid);
                        }
                        else
                        {
                            return NegotiateHelper.GetNegotiateResponse(header, request, m_securityProvider, state);
                        }
                    }
                    else
                    {
                        return new NegotiateResponseNotSupported();
                    }
                }
                else
                {
                    // [MS-CIFS] An SMB_COM_NEGOTIATE exchange MUST be completed before any other SMB messages are sent to the server
                    header.Status = NTStatus.STATUS_INVALID_SMB;
                    return new ErrorResponse(command.CommandName);
                }
            }
            else if (command is NegotiateRequest)
            {
                // There MUST be only one SMB_COM_NEGOTIATE exchange per SMB connection.
                // Subsequent SMB_COM_NEGOTIATE requests received by the server MUST be rejected with error responses.
                header.Status = NTStatus.STATUS_INVALID_SMB;
                return new ErrorResponse(command.CommandName);
            }
            else
            {
                return ProcessSMB1Command(header, command, (SMB1ConnectionState)state);
            }
        }

        private List<SMB1Command> ProcessSMB1Command(SMB1Header header, SMB1Command command, SMB1ConnectionState state)
        {
            if (command is SessionSetupAndXRequest)
            {
                SessionSetupAndXRequest request = (SessionSetupAndXRequest)command;
                state.MaxBufferSize = request.MaxBufferSize;
                return SessionSetupHelper.GetSessionSetupResponse(header, request, m_securityProvider, state);
            }
            else if (command is SessionSetupAndXRequestExtended)
            {
                SessionSetupAndXRequestExtended request = (SessionSetupAndXRequestExtended)command;
                state.MaxBufferSize = request.MaxBufferSize;
                return SessionSetupHelper.GetSessionSetupResponseExtended(header, request, m_securityProvider, state);
            }
            else if (command is EchoRequest)
            {
                return EchoHelper.GetEchoResponse((EchoRequest)command);
            }
            else
            {
                SMB1Session session = state.GetSession(header.UID);
                if (session == null)
                {
                    header.Status = NTStatus.STATUS_USER_SESSION_DELETED;
                    return new ErrorResponse(command.CommandName);
                }

                if (command is TreeConnectAndXRequest)
                {
                    return TreeConnectHelper.GetTreeConnectResponse(header, (TreeConnectAndXRequest)command, state, m_services, m_shares);
                }
                else if (command is LogoffAndXRequest)
                {
                    state.LogToServer(Severity.Information, "Logoff: User '{0}' logged off. (UID: {1})", session.UserName, header.UID);
                    m_securityProvider.DeleteSecurityContext(ref session.SecurityContext.AuthenticationContext);
                    state.RemoveSession(header.UID);
                    return new LogoffAndXResponse();
                }
                else
                {
                    ISMBShare share = session.GetConnectedTree(header.TID);
                    if (share == null)
                    {
                        state.LogToServer(Severity.Verbose, "{0} failed. Invalid TID (UID: {1}, TID: {2}).", command.CommandName, header.UID, header.TID);
                        header.Status = NTStatus.STATUS_SMB_BAD_TID;
                        return new ErrorResponse(command.CommandName);
                    }

                    if (command is CreateDirectoryRequest)
                    {
                        return FileStoreResponseHelper.GetCreateDirectoryResponse(header, (CreateDirectoryRequest)command, share, state);
                    }
                    else if (command is DeleteDirectoryRequest)
                    {
                        return FileStoreResponseHelper.GetDeleteDirectoryResponse(header, (DeleteDirectoryRequest)command, share, state);
                    }
                    else if (command is CloseRequest)
                    {
                        return CloseHelper.GetCloseResponse(header, (CloseRequest)command, share, state);
                    }
                    else if (command is FlushRequest)
                    {
                        return ReadWriteResponseHelper.GetFlushResponse(header, (FlushRequest)command, share, state);
                    }
                    else if (command is DeleteRequest)
                    {
                        return FileStoreResponseHelper.GetDeleteResponse(header, (DeleteRequest)command, share, state);
                    }
                    else if (command is RenameRequest)
                    {
                        return FileStoreResponseHelper.GetRenameResponse(header, (RenameRequest)command, share, state);
                    }
                    else if (command is QueryInformationRequest)
                    {
                        return FileStoreResponseHelper.GetQueryInformationResponse(header, (QueryInformationRequest)command, share, state);
                    }
                    else if (command is SetInformationRequest)
                    {
                        return FileStoreResponseHelper.GetSetInformationResponse(header, (SetInformationRequest)command, share, state);
                    }
                    else if (command is ReadRequest)
                    {
                        return ReadWriteResponseHelper.GetReadResponse(header, (ReadRequest)command, share, state);
                    }
                    else if (command is WriteRequest)
                    {
                        return ReadWriteResponseHelper.GetWriteResponse(header, (WriteRequest)command, share, state);
                    }
                    else if (command is CheckDirectoryRequest)
                    {
                        return FileStoreResponseHelper.GetCheckDirectoryResponse(header, (CheckDirectoryRequest)command, share, state);
                    }
                    else if (command is WriteRawRequest)
                    {
                        // [MS-CIFS] 3.3.5.26 - Receiving an SMB_COM_WRITE_RAW Request:
                        // the server MUST verify that the Server.Capabilities include CAP_RAW_MODE,
                        // If an error is detected [..] the Write Raw operation MUST fail and
                        // the server MUST return a Final Server Response [..] with the Count field set to zero.
                        return new WriteRawFinalResponse();
                    }
                    else if (command is SetInformation2Request)
                    {
                        return FileStoreResponseHelper.GetSetInformation2Response(header, (SetInformation2Request)command, share, state);
                    }
                    else if (command is LockingAndXRequest)
                    {
                        return LockingHelper.GetLockingAndXResponse(header, (LockingAndXRequest)command, share, state);
                    }
                    else if (command is OpenAndXRequest)
                    {
                        return OpenAndXHelper.GetOpenAndXResponse(header, (OpenAndXRequest)command, share, state);
                    }
                    else if (command is ReadAndXRequest)
                    {
                        return ReadWriteResponseHelper.GetReadResponse(header, (ReadAndXRequest)command, share, state);
                    }
                    else if (command is WriteAndXRequest)
                    {
                        return ReadWriteResponseHelper.GetWriteResponse(header, (WriteAndXRequest)command, share, state);
                    }
                    else if (command is FindClose2Request)
                    {
                        return CloseHelper.GetFindClose2Response(header, (FindClose2Request)command, state);
                    }
                    else if (command is TreeDisconnectRequest)
                    {
                        return TreeConnectHelper.GetTreeDisconnectResponse(header, (TreeDisconnectRequest)command, share, state);
                    }
                    else if (command is TransactionRequest) // Both TransactionRequest and Transaction2Request
                    {
                        return TransactionHelper.GetTransactionResponse(header, (TransactionRequest)command, share, state);
                    }
                    else if (command is TransactionSecondaryRequest) // Both TransactionSecondaryRequest and Transaction2SecondaryRequest
                    {
                        return TransactionHelper.GetTransactionResponse(header, (TransactionSecondaryRequest)command, share, state);
                    }
                    else if (command is NTTransactRequest)
                    {
                        return NTTransactHelper.GetNTTransactResponse(header, (NTTransactRequest)command, share, state);
                    }
                    else if (command is NTTransactSecondaryRequest)
                    {
                        return NTTransactHelper.GetNTTransactResponse(header, (NTTransactSecondaryRequest)command, share, state);
                    }
                    else if (command is NTCreateAndXRequest)
                    {
                        return NTCreateHelper.GetNTCreateResponse(header, (NTCreateAndXRequest)command, share, state);
                    }
                    else if (command is NTCancelRequest)
                    {
                        CancelHelper.ProcessNTCancelRequest(header, (NTCancelRequest)command, share, state);
                        // [MS-CIFS] The SMB_COM_NT_CANCEL command MUST NOT send a response.
                        return new List<SMB1Command>();
                    }
                }
            }

            header.Status = NTStatus.STATUS_SMB_BAD_COMMAND;
            return new ErrorResponse(command.CommandName);
        }

        internal static void EnqueueMessage(ConnectionState state, SMB1Message response)
        {
            SessionMessagePacket packet = new SessionMessagePacket();
            packet.Trailer = response.GetBytes();
            state.SendQueue.Enqueue(packet);
            state.LogToServer(Severity.Verbose, "SMB1 message queued: {0} responses, First response: {1}, Packet length: {2}", response.Commands.Count, response.Commands[0].CommandName.ToString(), packet.Length);
        }

        private static void PrepareResponseHeader(SMB1Header responseHeader, SMB1Header requestHeader)
        {
            responseHeader.Status = NTStatus.STATUS_SUCCESS;
            responseHeader.Flags = HeaderFlags.CaseInsensitive | HeaderFlags.CanonicalizedPaths | HeaderFlags.Reply;
            responseHeader.Flags2 = HeaderFlags2.NTStatusCode;
            if ((requestHeader.Flags2 & HeaderFlags2.LongNamesAllowed) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.LongNamesAllowed | HeaderFlags2.LongNameUsed;
            }
            if ((requestHeader.Flags2 & HeaderFlags2.ExtendedAttributes) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.ExtendedAttributes;
            }
            if ((requestHeader.Flags2 & HeaderFlags2.ExtendedSecurity) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.ExtendedSecurity;
            }
            if ((requestHeader.Flags2 & HeaderFlags2.Unicode) > 0)
            {
                responseHeader.Flags2 |= HeaderFlags2.Unicode;
            }
            responseHeader.MID = requestHeader.MID;
            responseHeader.PID = requestHeader.PID;
            responseHeader.UID = requestHeader.UID;
            responseHeader.TID = requestHeader.TID;
        }
    }
}