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
    internal class NTTransactHelper
    {
        /// <summary>
        /// The client MUST send as many secondary requests as are needed to complete the transfer of the transaction request.
        /// </summary>
        internal static List<SMB1Command> GetNTTransactResponse(SMB1Header header, NTTransactRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            if (request.TransParameters.Length < request.TotalParameterCount ||
                request.TransData.Length < request.TotalDataCount)
            {
                // A secondary transaction request is pending
                ProcessStateObject processState = state.CreateProcessState(header.PID);
                processState.SubcommandID = (ushort)request.Function;
                processState.MaxParameterCount = request.MaxParameterCount;
                processState.MaxDataCount = request.MaxDataCount;
                processState.TransactionSetup = request.Setup;
                processState.TransactionParameters = new byte[request.TotalParameterCount];
                processState.TransactionData = new byte[request.TotalDataCount];
                ByteWriter.WriteBytes(processState.TransactionParameters, 0, request.TransParameters);
                ByteWriter.WriteBytes(processState.TransactionData, 0, request.TransData);
                processState.TransactionParametersReceived += request.TransParameters.Length;
                processState.TransactionDataReceived += request.TransData.Length;
                return new NTTransactInterimResponse();
            }
            else
            {
                // We have a complete command
                return GetCompleteNTTransactResponse(header, request.MaxParameterCount, request.MaxDataCount, request.Function, request.Setup, request.TransParameters, request.TransData, share, state);
            }
        }

        /// <summary>
        /// There are no secondary response messages.
        /// The client MUST send as many secondary requests as are needed to complete the transfer of the transaction request.
        /// </summary>
        internal static List<SMB1Command> GetNTTransactResponse(SMB1Header header, NTTransactSecondaryRequest request, ISMBShare share, SMB1ConnectionState state)
        {
            ProcessStateObject processState = state.GetProcessState(header.PID);
            if (processState == null)
            {
                throw new InvalidDataException();
            }
            ByteWriter.WriteBytes(processState.TransactionParameters, (int)request.ParameterDisplacement, request.TransParameters);
            ByteWriter.WriteBytes(processState.TransactionData, (int)request.DataDisplacement, request.TransData);
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
                return GetCompleteNTTransactResponse(header, processState.MaxParameterCount, processState.MaxDataCount, (NTTransactSubcommandName)processState.SubcommandID, processState.TransactionSetup, processState.TransactionParameters, processState.TransactionData, share, state);
            }
        }

        internal static List<SMB1Command> GetCompleteNTTransactResponse(SMB1Header header, uint maxParameterCount, uint maxDataCount, NTTransactSubcommandName subcommandName, byte[] requestSetup, byte[] requestParameters, byte[] requestData, ISMBShare share, SMB1ConnectionState state)
        {
            NTTransactSubcommand subcommand;
            try
            {
                subcommand = NTTransactSubcommand.GetSubcommandRequest(subcommandName, requestSetup, requestParameters, requestData, header.UnicodeFlag);
            }
            catch
            {
                // [MS-CIFS] If the Function code is not defined, the server MUST return STATUS_INVALID_SMB.
                header.Status = NTStatus.STATUS_INVALID_SMB;
                return new ErrorResponse(CommandName.SMB_COM_NT_TRANSACT);
            }
            state.LogToServer(Severity.Verbose, "Received complete SMB_COM_NT_TRANSACT subcommand: {0}", subcommand.SubcommandName);
            NTTransactSubcommand subcommandResponse = null;

            if (subcommand is NTTransactCreateRequest)
            {
                header.Status = NTStatus.STATUS_NOT_IMPLEMENTED;
            }
            else if (subcommand is NTTransactIOCTLRequest)
            {
                subcommandResponse = GetSubcommandResponse(header, maxDataCount, (NTTransactIOCTLRequest)subcommand, share, state);
            }
            else if (subcommand is NTTransactSetSecurityDescriptorRequest)
            {
                subcommandResponse = GetSubcommandResponse(header, (NTTransactSetSecurityDescriptorRequest)subcommand, share, state);
            }
            else if (subcommand is NTTransactNotifyChangeRequest)
            {
                NotifyChangeHelper.ProcessNTTransactNotifyChangeRequest(header, maxParameterCount, (NTTransactNotifyChangeRequest)subcommand, share, state);
                if (header.Status == NTStatus.STATUS_PENDING)
                {
                    return new List<SMB1Command>();
                }
            }
            else if (subcommand is NTTransactQuerySecurityDescriptorRequest)
            {
                subcommandResponse = GetSubcommandResponse(header, maxDataCount, (NTTransactQuerySecurityDescriptorRequest)subcommand, share, state);
            }
            else
            {
                // [MS-CIFS] If the Function code is defined but not implemented, the server MUST return STATUS_SMB_BAD_COMMAND.
                header.Status = NTStatus.STATUS_SMB_BAD_COMMAND;
            }

            if (header.Status != NTStatus.STATUS_SUCCESS && (header.Status != NTStatus.STATUS_BUFFER_OVERFLOW || subcommandResponse == null))
            {
                return new ErrorResponse(CommandName.SMB_COM_NT_TRANSACT);
            }

            byte[] responseSetup = subcommandResponse.GetSetup();
            byte[] responseParameters = subcommandResponse.GetParameters(header.UnicodeFlag);
            byte[] responseData = subcommandResponse.GetData();
            return GetNTTransactResponse(responseSetup, responseParameters, responseData, state.MaxBufferSize);
        }

        private static NTTransactIOCTLResponse GetSubcommandResponse(SMB1Header header, uint maxDataCount, NTTransactIOCTLRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            string ctlCode = Enum.IsDefined(typeof(IoControlCode), subcommand.FunctionCode) ? ((IoControlCode)subcommand.FunctionCode).ToString() : ("0x" + subcommand.FunctionCode.ToString("X8"));
            if (!subcommand.IsFsctl)
            {
                // [MS-SMB] If the IsFsctl field is set to zero, the server SHOULD fail the request with STATUS_NOT_SUPPORTED
                state.LogToServer(Severity.Verbose, "IOCTL: Non-FSCTL requests are not supported. CTL Code: {0}", ctlCode);
                header.Status = NTStatus.STATUS_NOT_SUPPORTED;
                return null;
            }

            OpenFileObject openFile = session.GetOpenFileObject(subcommand.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. Invalid FID. (UID: {1}, TID: {2}, FID: {3})", ctlCode, header.UID, header.TID, subcommand.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            int maxOutputLength = (int)maxDataCount;
            byte[] output;
            header.Status = share.FileStore.DeviceIOControl(openFile.Handle, subcommand.FunctionCode, subcommand.Data, out output, maxOutputLength);
            if (header.Status != NTStatus.STATUS_SUCCESS && header.Status != NTStatus.STATUS_BUFFER_OVERFLOW)
            {
                state.LogToServer(Severity.Verbose, "IOCTL failed. CTL Code: {0}. NTStatus: {1}. (FID: {2})", ctlCode, header.Status, subcommand.FID);
                return null;
            }

            state.LogToServer(Severity.Verbose, "IOCTL succeeded. CTL Code: {0}. (FID: {1})", ctlCode, subcommand.FID);
            NTTransactIOCTLResponse response = new NTTransactIOCTLResponse();
            response.Data = output;
            return response;
        }

        private static NTTransactSetSecurityDescriptorResponse GetSubcommandResponse(SMB1Header header, NTTransactSetSecurityDescriptorRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(subcommand.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "SetSecurityInformation failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, subcommand.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            header.Status = share.FileStore.SetSecurityInformation(openFile.Handle, subcommand.SecurityInformation, subcommand.SecurityDescriptor);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "SetSecurityInformation on '{0}{1}' failed. Security information: 0x{2}, NTStatus: {3}. (FID: {4})", share.Name, openFile.Path, subcommand.SecurityInformation.ToString("X"), header.Status, subcommand.FID);
                return null;
            }

            state.LogToServer(Severity.Verbose, "SetSecurityInformation on '{0}{1}' succeeded. Security information: 0x{2}. (FID: {3})", share.Name, openFile.Path, subcommand.SecurityInformation.ToString("X"), subcommand.FID);
            NTTransactSetSecurityDescriptorResponse response = new NTTransactSetSecurityDescriptorResponse();
            return response;
        }

        private static NTTransactQuerySecurityDescriptorResponse GetSubcommandResponse(SMB1Header header, uint maxDataCount, NTTransactQuerySecurityDescriptorRequest subcommand, ISMBShare share, SMB1ConnectionState state)
        {
            SMB1Session session = state.GetSession(header.UID);
            OpenFileObject openFile = session.GetOpenFileObject(subcommand.FID);
            if (openFile == null)
            {
                state.LogToServer(Severity.Verbose, "GetSecurityInformation failed. Invalid FID. (UID: {0}, TID: {1}, FID: {2})", header.UID, header.TID, subcommand.FID);
                header.Status = NTStatus.STATUS_INVALID_HANDLE;
                return null;
            }

            int maxOutputLength = (int)maxDataCount;
            SecurityDescriptor securityDescriptor;
            header.Status = share.FileStore.GetSecurityInformation(out securityDescriptor, openFile.Handle, subcommand.SecurityInfoFields);
            if (header.Status != NTStatus.STATUS_SUCCESS)
            {
                state.LogToServer(Severity.Verbose, "GetSecurityInformation on '{0}{1}' failed. Security information: 0x{2}, NTStatus: {3}. (FID: {4})", share.Name, openFile.Path, subcommand.SecurityInfoFields.ToString("X"), header.Status, subcommand.FID);
                return null;
            }

            NTTransactQuerySecurityDescriptorResponse response = new NTTransactQuerySecurityDescriptorResponse();
            response.LengthNeeded = (uint)securityDescriptor.Length;
            if (response.LengthNeeded <= maxDataCount)
            {
                state.LogToServer(Severity.Verbose, "GetSecurityInformation on '{0}{1}' succeeded. Security information: 0x{2}. (FID: {3})", share.Name, openFile.Path, subcommand.SecurityInfoFields.ToString("X"), subcommand.FID);
                response.SecurityDescriptor = securityDescriptor;
            }
            else
            {
                state.LogToServer(Severity.Verbose, "GetSecurityInformation on '{0}{1}' failed. Security information: 0x{2}, NTStatus: STATUS_BUFFER_TOO_SMALL. (FID: {3})", share.Name, openFile.Path, subcommand.SecurityInfoFields.ToString("X"), subcommand.FID);
                header.Status = NTStatus.STATUS_BUFFER_TOO_SMALL;
            }
            return response;
        }

        internal static List<SMB1Command> GetNTTransactResponse(byte[] responseSetup, byte[] responseParameters, byte[] responseData, int maxBufferSize)
        {
            List<SMB1Command> result = new List<SMB1Command>();
            NTTransactResponse response = new NTTransactResponse();
            result.Add(response);
            int responseSize = NTTransactResponse.CalculateMessageSize(responseSetup.Length, responseParameters.Length, responseData.Length);
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
                    NTTransactResponse additionalResponse = new NTTransactResponse();
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