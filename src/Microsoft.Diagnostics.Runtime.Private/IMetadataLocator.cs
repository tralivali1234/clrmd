// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

namespace Microsoft.Diagnostics.Runtime.Private
{
    [ComImport, InterfaceType(ComInterfaceType.InterfaceIsIUnknown), Guid("aa8fa804-bc05-4642-b2c5-c353ed22fc63")]
    public interface IMetadataLocator
    {
        [PreserveSig]
        int GetMetadata([In, MarshalAs(UnmanagedType.LPWStr)] string imagePath,
                        uint imageTimestamp,
                        uint imageSize,
                        IntPtr mvid, // (guid, unused)
                        uint mdRva,
                        uint flags,  // unused
                        uint bufferSize,
                        [Out, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 6)]
                        byte[] buffer,
                        IntPtr ptr);
    }
}
