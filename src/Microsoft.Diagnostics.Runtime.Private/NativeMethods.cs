// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;


namespace Microsoft.Diagnostics.Runtime.Private
{
    internal class NativeMethods
    {
        private const string Kernel32LibraryName = "kernel32.dll";

        public const uint FILE_MAP_READ = 4;
        [DllImportAttribute(Kernel32LibraryName)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool FreeLibrary(IntPtr hModule);

        public static IntPtr LoadLibrary(string lpFileName)
        {
            return LoadLibraryEx(lpFileName, 0, LoadLibraryFlags.NoFlags);
        }

        [DllImport(Kernel32LibraryName, SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(String fileName, int hFile, LoadLibraryFlags dwFlags);

        [Flags]
        public enum LoadLibraryFlags : uint
        {
            NoFlags = 0x00000000,
            DontResolveDllReferences = 0x00000001,
            LoadIgnoreCodeAuthzLevel = 0x00000010,
            LoadLibraryAsDatafile = 0x00000002,
            LoadLibraryAsDatafileExclusive = 0x00000040,
            LoadLibraryAsImageResource = 0x00000020,
            LoadWithAlteredSearchPath = 0x00000008
        }


        [Flags]
        public enum PageProtection : uint
        {
            NoAccess = 0x01,
            Readonly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            Guard = 0x100,
            NoCache = 0x200,
            WriteCombine = 0x400,
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process([In] IntPtr hProcess, [Out] out bool isWow64);

        [DllImport("version.dll")]
        internal static extern bool GetFileVersionInfo(string sFileName, int handle, int size, byte[] infoBuffer);

        [DllImport("version.dll")]
        internal static extern int GetFileVersionInfoSize(string sFileName, out int handle);

        [DllImport("version.dll")]
        internal static extern bool VerQueryValue(byte[] pBlock, string pSubBlock, out IntPtr val, out int len);

        private const int VS_FIXEDFILEINFO_size = 0x34;
        public static short IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

        [DefaultDllImportSearchPaths(DllImportSearchPath.LegacyBehavior)]
        [DllImport("dbgeng.dll")]
        internal static extern uint DebugCreate(ref Guid InterfaceId, [MarshalAs(UnmanagedType.IUnknown)] out object Interface);
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        internal delegate int CreateDacInstance([In, ComAliasName("REFIID")] ref Guid riid,
                                       [In, MarshalAs(UnmanagedType.Interface)] IDacDataTarget data,
                                       [Out, MarshalAs(UnmanagedType.IUnknown)] out object ppObj);


        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
    }
}