/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 *
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using SMBLibrary.SMB1;
using System;
using System.Collections.Generic;
using System.IO;
using Utilities;

namespace SMBLibrary.Server.SMB1
{
    internal class TransactionHelper
    {
        /// <summary>
        /// The client MUST send as many secondary requests as are needed to complete the transfer of the transaction request.
        /// The server MUST respond to the transaction request as a whole.
        /// </summary>
        internal static List<SMB1Command> GetTransactionResponse(SMB1Header header, TransactionRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            if (request.TransParameters.Length < request.TotalParameterCount ||
                request.TransData.Length < request.TotalDataCount)
            {
                // A secondary transaction request is pending
                ProcessStateObject processState = state.CreateProcessState(header.PID);
                processState.MaxParameterCount = request.MaxParameterCount;
                processState.MaxDataCount = request.MaxDataCount;
                processState.Timeout = request.Timeout;
                processState.Name = request.Name;
                processState.TransactionSetup = request.Setup;
                processState.TransactionParameters = new byte[request.TotalParameterCount];
                processState.TransactionData = new byte[request.TotalDataCount];
                ByteWriter.WriteBytes(processState.TransactionParameters, 0, request.TransParameters);
                ByteWriter.WriteBytes(processState.TransactionData, 0, request.TransData);
                processState.TransactionParametersReceived += request.TransParameters.Length;
                processState.TransactionDataReceived += request.TransData.Length;
                if (request is Transaction2Request)
                {
                    return new Transaction2InterimResponse();
                }
                else
                {
                    return new TransactionInterimResponse();
                }
            }
            else
            {
                // We have a complete command
                if (request is Transaction2Request)
                {
                    return GetCompleteTransaction2Response(header, request.MaxDataCount, request.Setup, request.TransParameters, request.TransData, share, state);
                }
                else
                {
                    return GetCompleteTransactionResponse(header, request.MaxDataCount, request.Timeout, request.Name, request.Setup, request.TransParameters, request.TransData, share, state);
                }
            }
        }

        /// <summary>
        /// There are no secondary response messages.
        /// The client MUST send as many secondary requests as are needed to complete the transfer of the transaction request.
        /// The server MUST respond to the transaction request as a whole.
        /// </summary>
        internal static List<SMB1Command> GetTransactionResponse(SMB1Header header, TransactionSecondaryRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            ProcessStateObject processState = state.GetProcessState(header.PID);
            if (processState == null)
            {
                throw new InvalidDataException();
            }
            ByteWriter.WriteBytes(processState.TransactionParameters, request.ParameterDisplacement, request.TransParameters);
            ByteWriter.WriteBytes(processState.TransactionData, request.DataDisplacement, request.TransData);
            processState.TransactionParametersReceived += request.TransParameters.Length;
            processState.TransactionDataReceived += request.TransData.Length;

            if (processState.TransactionParametersReceived < processState.TransactionParameters.Length ||
                processState.TransactionDataReceived < processState.TransactionData.Length)
            {
                return new List<SMB1Command>();
            }
            else
            {
                // We have a complete command
                state.RemoveProcessState(header.PID);
                if (request is Transaction2SecondaryRequest)
                {
                    return GetCompleteTransaction2Response(header, processState.MaxDataCount, processState.TransactionSetup, processState.TransactionParameters, processState.TransactionData, share, state);
                }
                else
                {
                    return GetCompleteTransactionResponse(header, processState.MaxDataCount, processState.Timeout, processState.Name, processState.TransactionSetup, processState.TransactionParameters, processState.TransactionData, share, state);
                }
            }
        }

        internal static List<SMB1Command> GetCompleteTransactionResponse(SMB1Header header, uint maxDataCount, uint timeout, string name, byte[] requestSetup, byte[] requestParameters, byte[] requestData, ISMBShare share, SMB1ConnectionState state)
        {
            if (String.Equals(name, @"\PIPE\lanman", StringComparison.OrdinalIgnoreCase))
            {
                // [MS-RAP] Remote Administration Protocol request
                state.LogToServer(Severity.Debug, "Remote Administration Protocol requests are not implemented");
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
                return new ErrorResponse(CommandName.SMB_COM_TRANSACTION);
            }

            TransactionSubcommand subcommand;
            try
            {
                subcommand = TransactionSubcommand.GetSubcommandRequest(requestSetup, requestParameters, requestData, header.UnicodeFlag);
            }
            catch
            {
                header.Status = NTStatus.STATUS_INVALID_SMB;
                return new ErrorResponse(CommandName.SMB_COM_TRANSACTION);
            }
            state.LogToServer(Severity.Verbose, "Received complete SMB_COM_TRANSACTION subcommand: {0}", subcommand.SubcommandName);
            TransactionSubcommand subcommandResponse = null;

            if (subcommand is TransactionSetNamedPipeStateRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionRawReadNamedPipeRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionQueryNamedPipeStateRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionQueryNamedPipeInfoRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionPeekNamedPipeRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionTransactNamedPipeRequest)
            {
                subcommandResponse = TransactionSubcommandHelper.GetSubcommandResponse(header, maxDataCount, (TransactionTransactNamedPipeRequest)subcommand, share, state);
            }
            else if (subcommand is TransactionRawWriteNamedPipeRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionReadNamedPipeRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionWriteNamedPipeRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is TransactionWaitNamedPipeRequest)
            {
                TransactionSubcommandHelper.ProcessSubcommand(header, timeout, name, (TransactionWaitNamedPipeRequest)subcommand, share, state);
            }
            else if (subcommand is TransactionCallNamedPipeRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else
            {
                header.Status = NTStatus.STATUS_SMB_BAD_COMMAND;
            }

            if (header.Status != NTStatus.STATUS_SUCCESS && (header.Status != NTStatus.STATUS_BUFFER_OVERFLOW || subcommandResponse == null))
            {
                return new ErrorResponse(CommandName.SMB_COM_TRANSACTION);
            }

            byte[] responseSetup = subcommandResponse.GetSetup();
            byte[] responseParameters = subcommandResponse.GetParameters();
            byte[] responseData = subcommandResponse.GetData(header.UnicodeFlag);
            return GetTransactionResponse(false, responseSetup, responseParameters, responseData, state.MaxBufferSize);
        }

        internal static List<SMB1Command> GetCompleteTransaction2Response(SMB1Header header, uint maxDataCount, byte[] requestSetup, byte[] requestParameters, byte[] requestData, ISMBShare share, SMB1ConnectionState state)
        {
            Transaction2Subcommand subcommand;
            try
            {
                subcommand = Transaction2Subcommand.GetSubcommandRequest(requestSetup, requestParameters, requestData, header.UnicodeFlag);
            }
            catch
            {
                header.Status = NTStatus.STATUS_INVALID_SMB;
                return new ErrorResponse(CommandName.SMB_COM_TRANSACTION2);
            }
            state.LogToServer(Severity.Verbose, "Received complete SMB_COM_TRANSACTION2 subcommand: {0}", subcommand.SubcommandName);
            Transaction2Subcommand subcommandResponse = null;

            if (subcommand is Transaction2FindFirst2Request)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, maxDataCount, (Transaction2FindFirst2Request)subcommand, share, state);
            }
            else if (subcommand is Transaction2FindNext2Request)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, maxDataCount, (Transaction2FindNext2Request)subcommand, share, state);
            }
            else if (subcommand is Transaction2QueryFSInformationRequest)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, maxDataCount, (Transaction2QueryFSInformationRequest)subcommand, share, state);
            }
            else if (subcommand is Transaction2SetFSInformationRequest)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, (Transaction2SetFSInformationRequest)subcommand, share, state);
            }
            else if (subcommand is Transaction2QueryPathInformationRequest)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, maxDataCount, (Transaction2QueryPathInformationRequest)subcommand, share, state);
            }
            else if (subcommand is Transaction2SetPathInformationRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is Transaction2QueryFileInformationRequest)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, maxDataCount, (Transaction2QueryFileInformationRequest)subcommand, share, state);
            }
            else if (subcommand is Transaction2SetFileInformationRequest)
            {
                subcommandResponse = Transaction2SubcommandHelper.GetSubcommandResponse(header, (Transaction2SetFileInformationRequest)subcommand, share, state);
            }
            else if (subcommand is Transaction2CreateDirectoryRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is Transaction2GetDfsReferralRequest)
            {
                header.Status = NTStatus.STATUS_NO_SUCH_DEVICE;
            }
            else
            {
                header.Status = NTStatus.STATUS_SMB_BAD_COMMAND;
            }

            if (header.Status != NTStatus.STATUS_SUCCESS && (header.Status != NTStatus.STATUS_BUFFER_OVERFLOW || subcommandResponse == null))
            {
                return new ErrorResponse(CommandName.SMB_COM_TRANSACTION2);
            }

            byte[] responseSetup = subcommandResponse.GetSetup();
            byte[] responseParameters = subcommandResponse.GetParameters(header.UnicodeFlag);
            byte[] responseData = subcommandResponse.GetData(header.UnicodeFlag);
            return GetTransactionResponse(true, responseSetup, responseParameters, responseData, state.MaxBufferSize);
        }

        internal static List<SMB1Command> GetTransactionResponse(bool transaction2Response, byte[] responseSetup, byte[] responseParameters, byte[] responseData, int maxBufferSize)
        {
            List<SMB1Command> result = new List<SMB1Command>();
            TransactionResponse response;
            if (transaction2Response)
            {
                response = new Transaction2Response();
            }
            else
            {
                response = new TransactionResponse();
            }
            result.Add(response);
            int responseSize = TransactionResponse.CalculateMessageSize(responseSetup.Length, responseParameters.Length, responseData.Length);
            if (responseSize <= maxBufferSize)
            {
                response.Setup = responseSetup;
                response.TotalParameterCount = (ushort)responseParameters.Length;
                response.TotalDataCount = (ushort)responseData.Length;
                response.TransParameters = responseParameters;
                response.TransData = responseData;
            }
            else
            {
                int currentDataLength = maxBufferSize - (responseSize - responseData.Length);
                byte[] buffer = new byte[currentDataLength];
                Array.Copy(responseData, 0, buffer, 0, currentDataLength);
                response.Setup = responseSetup;
                response.TotalParameterCount = (ushort)responseParameters.Length;
                response.TotalDataCount = (ushort)responseData.Length;
                response.TransParameters = responseParameters;
                response.TransData = buffer;

                int dataBytesLeftToSend = responseData.Length - currentDataLength;
                while (dataBytesLeftToSend > 0)
                {
                    TransactionResponse additionalResponse;
                    if (transaction2Response)
                    {
                        additionalResponse = new Transaction2Response();
                    }
                    else
                    {
                        additionalResponse = new TransactionResponse();
                    }
                    currentDataLength = dataBytesLeftToSend;
                    responseSize = TransactionResponse.CalculateMessageSize(0, 0, dataBytesLeftToSend);
                    if (responseSize > maxBufferSize)
                    {
                        currentDataLength = maxBufferSize - (responseSize - dataBytesLeftToSend);
                    }
                    buffer = new byte[currentDataLength];
                    int dataBytesSent = responseData.Length - dataBytesLeftToSend;
                    Array.Copy(responseData, dataBytesSent, buffer, 0, currentDataLength);
                    additionalResponse.TotalParameterCount = (ushort)responseParameters.Length;
                    additionalResponse.TotalDataCount = (ushort)responseData.Length;
                    additionalResponse.TransData = buffer;
                    additionalResponse.ParameterDisplacement = (ushort)response.TransParameters.Length;
                    additionalResponse.DataDisplacement = (ushort)dataBytesSent;
                    result.Add(additionalResponse);

                    dataBytesLeftToSend -= currentDataLength;
                }
            }
            return result;
        }
    }
}