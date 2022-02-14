using SMBLibrary.RPC;
using System;
using Utilities;

namespace SMBLibrary.Client.Helpers
{
    public class RPCCallHelper : IDisposable
    {
        private ISMBClient Client;
        private ISMBFileStore NamedPipeShare;
        private string ServicePipeName;
        private Guid ServiceInterfaceGuid;
        private uint ServiceVersion;
        private object pipeHandle;
        private int maxTransmitFragmentSize;

        private bool disposedValue;

        public RPCCallHelper(ISMBClient client, string pipeName, Guid interfaceGuid, uint interfaceVersion)
        {
            Client = client;
            ServicePipeName = pipeName;
            ServiceInterfaceGuid = interfaceGuid;
            ServiceVersion = interfaceVersion;
        }

        public NTStatus BindPipe()
        {
            NTStatus status;
            NamedPipeShare = Client.TreeConnect("IPC$", out status);
            if (NamedPipeShare == null)
            {
                return status;
            }
            status = NamedPipeHelper.BindPipe(NamedPipeShare, ServicePipeName, ServiceInterfaceGuid, ServiceVersion, out pipeHandle, out maxTransmitFragmentSize);
            return status;
        }

        public NTStatus ExecuteCall<I, O>(ushort OpNum, I inputArgs, out O outputData) where I : IRPCRequest
        {
            byte[] output;
            NTStatus status;
            outputData = default(O);

            RequestPDU requestPDU = new RequestPDU();
            requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            requestPDU.OpNum = OpNum;
            requestPDU.Data = inputArgs.GetBytes();
            requestPDU.AllocationHint = (uint)requestPDU.Data.Length;
            byte[] input = requestPDU.GetBytes();
            status = NamedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out output, maxTransmitFragmentSize);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            ResponsePDU responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                status = NTStatus.STATUS_NOT_SUPPORTED;
                return status;
            }

            byte[] responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                status = NamedPipeShare.ReadFile(out output, pipeHandle, 0, maxTransmitFragmentSize);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return status;
                }
                responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return status;
                }
                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }
            outputData = (O)Activator.CreateInstance(typeof(O), new object[] { responseData });
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus ExecuteCall<O>(ushort OpNum, byte[] inputArgs, out O outputData)
        {
            byte[] output;
            NTStatus status;
            outputData = default(O);

            RequestPDU requestPDU = new RequestPDU();
            requestPDU.Flags = PacketFlags.FirstFragment | PacketFlags.LastFragment;
            requestPDU.DataRepresentation.CharacterFormat = CharacterFormat.ASCII;
            requestPDU.DataRepresentation.ByteOrder = ByteOrder.LittleEndian;
            requestPDU.DataRepresentation.FloatingPointRepresentation = FloatingPointRepresentation.IEEE;
            requestPDU.OpNum = OpNum;
            requestPDU.Data = inputArgs;
            requestPDU.AllocationHint = (uint)requestPDU.Data.Length;
            byte[] input = requestPDU.GetBytes();
            status = NamedPipeShare.DeviceIOControl(pipeHandle, (uint)IoControlCode.FSCTL_PIPE_TRANSCEIVE, input, out output, maxTransmitFragmentSize);
            if (status != NTStatus.STATUS_SUCCESS)
            {
                return status;
            }
            ResponsePDU responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
            if (responsePDU == null)
            {
                status = NTStatus.STATUS_NOT_SUPPORTED;
                return status;
            }

            byte[] responseData = responsePDU.Data;
            while ((responsePDU.Flags & PacketFlags.LastFragment) == 0)
            {
                status = NamedPipeShare.ReadFile(out output, pipeHandle, 0, maxTransmitFragmentSize);
                if (status != NTStatus.STATUS_SUCCESS)
                {
                    return status;
                }
                responsePDU = RPCPDU.GetPDU(output, 0) as ResponsePDU;
                if (responsePDU == null)
                {
                    status = NTStatus.STATUS_NOT_SUPPORTED;
                    return status;
                }
                responseData = ByteUtils.Concatenate(responseData, responsePDU.Data);
            }
            outputData = (O)Activator.CreateInstance(typeof(O), new object[] { responseData });
            return NTStatus.STATUS_SUCCESS;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (pipeHandle != null && NamedPipeShare != null)
                    {
                        NamedPipeShare.CloseFile(pipeHandle);
                    }
                    if (NamedPipeShare != null)
                    {
                        NamedPipeShare.Disconnect();
                    }
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Ne changez pas ce code. Placez le code de nettoyage dans la méthode 'Dispose(bool disposing)'
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}