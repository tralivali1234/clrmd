// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

#pragma warning disable 649

namespace Microsoft.Diagnostics.Runtime.Private
{
    public enum ModuleExtentType
    {
        CLRDATA_MODULE_PE_FILE,
        CLRDATA_MODULE_PREJIT_FILE,
        CLRDATA_MODULE_MEMORY_STREAM,
        CLRDATA_MODULE_OTHER
    }

    public struct CLRDATA_MODULE_EXTENT
    {
        public ulong baseAddress;
        public uint length;
        public ModuleExtentType type;
    }

    public struct IlMap
    {
        public int ILOffset;
        public ulong StartAddress;
        public ulong EndAddress;
        public override string ToString()
        {
            return string.Format("{0,2:X} - [{1:X}-{2:X}]", ILOffset, StartAddress, EndAddress);
        }

#pragma warning disable 0169
        private int _reserved;
#pragma warning restore 0169
    }
}
