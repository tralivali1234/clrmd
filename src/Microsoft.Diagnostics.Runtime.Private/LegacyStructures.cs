// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;

namespace Microsoft.Diagnostics.Runtime.Private
{

    #region Dac Requests
    public class DacRequests
    {
        public const uint VERSION = 0xe0000000U;
        public const uint THREAD_STORE_DATA = 0xf0000000U;
        public const uint APPDOMAIN_STORE_DATA = 0xf0000001U;
        public const uint APPDOMAIN_LIST = 0xf0000002U;
        public const uint APPDOMAIN_DATA = 0xf0000003U;
        public const uint APPDOMAIN_NAME = 0xf0000004U;
        public const uint APPDOMAIN_APP_BASE = 0xf0000005U;
        public const uint APPDOMAIN_PRIVATE_BIN_PATHS = 0xf0000006U;
        public const uint APPDOMAIN_CONFIG_FILE = 0xf0000007U;
        public const uint ASSEMBLY_LIST = 0xf0000008U;
        public const uint FAILED_ASSEMBLY_LIST = 0xf0000009U;
        public const uint ASSEMBLY_DATA = 0xf000000aU;
        public const uint ASSEMBLY_NAME = 0xf000000bU;
        public const uint ASSEMBLY_DISPLAY_NAME = 0xf000000cU;
        public const uint ASSEMBLY_LOCATION = 0xf000000dU;
        public const uint FAILED_ASSEMBLY_DATA = 0xf000000eU;
        public const uint FAILED_ASSEMBLY_DISPLAY_NAME = 0xf000000fU;
        public const uint FAILED_ASSEMBLY_LOCATION = 0xf0000010U;
        public const uint THREAD_DATA = 0xf0000011U;
        public const uint THREAD_THINLOCK_DATA = 0xf0000012U;
        public const uint CONTEXT_DATA = 0xf0000013U;
        public const uint METHODDESC_DATA = 0xf0000014U;
        public const uint METHODDESC_IP_DATA = 0xf0000015U;
        public const uint METHODDESC_NAME = 0xf0000016U;
        public const uint METHODDESC_FRAME_DATA = 0xf0000017U;
        public const uint CODEHEADER_DATA = 0xf0000018U;
        public const uint THREADPOOL_DATA = 0xf0000019U;
        public const uint WORKREQUEST_DATA = 0xf000001aU;
        public const uint OBJECT_DATA = 0xf000001bU;
        public const uint FRAME_NAME = 0xf000001cU;
        public const uint OBJECT_STRING_DATA = 0xf000001dU;
        public const uint OBJECT_CLASS_NAME = 0xf000001eU;
        public const uint METHODTABLE_NAME = 0xf000001fU;
        public const uint METHODTABLE_DATA = 0xf0000020U;
        public const uint EECLASS_DATA = 0xf0000021U;
        public const uint FIELDDESC_DATA = 0xf0000022U;
        public const uint MANAGEDSTATICADDR = 0xf0000023U;
        public const uint MODULE_DATA = 0xf0000024U;
        public const uint MODULEMAP_TRAVERSE = 0xf0000025U;
        public const uint MODULETOKEN_DATA = 0xf0000026U;
        public const uint PEFILE_DATA = 0xf0000027U;
        public const uint PEFILE_NAME = 0xf0000028U;
        public const uint ASSEMBLYMODULE_LIST = 0xf0000029U;
        public const uint GCHEAP_DATA = 0xf000002aU;
        public const uint GCHEAP_LIST = 0xf000002bU;
        public const uint GCHEAPDETAILS_DATA = 0xf000002cU;
        public const uint GCHEAPDETAILS_STATIC_DATA = 0xf000002dU;
        public const uint HEAPSEGMENT_DATA = 0xf000002eU;
        public const uint UNITTEST_DATA = 0xf000002fU;
        public const uint ISSTUB = 0xf0000030U;
        public const uint DOMAINLOCALMODULE_DATA = 0xf0000031U;
        public const uint DOMAINLOCALMODULEFROMAPPDOMAIN_DATA = 0xf0000032U;
        public const uint DOMAINLOCALMODULE_DATA_FROM_MODULE = 0xf0000033U;
        public const uint SYNCBLOCK_DATA = 0xf0000034U;
        public const uint SYNCBLOCK_CLEANUP_DATA = 0xf0000035U;
        public const uint HANDLETABLE_TRAVERSE = 0xf0000036U;
        public const uint RCWCLEANUP_TRAVERSE = 0xf0000037U;
        public const uint EHINFO_TRAVERSE = 0xf0000038U;
        public const uint STRESSLOG_DATA = 0xf0000039U;
        public const uint JITLIST = 0xf000003aU;
        public const uint JIT_HELPER_FUNCTION_NAME = 0xf000003bU;
        public const uint JUMP_THUNK_TARGET = 0xf000003cU;
        public const uint LOADERHEAP_TRAVERSE = 0xf000003dU;
        public const uint MANAGER_LIST = 0xf000003eU;
        public const uint JITHEAPLIST = 0xf000003fU;
        public const uint CODEHEAP_LIST = 0xf0000040U;
        public const uint METHODTABLE_SLOT = 0xf0000041U;
        public const uint VIRTCALLSTUBHEAP_TRAVERSE = 0xf0000042U;
        public const uint NESTEDEXCEPTION_DATA = 0xf0000043U;
        public const uint USEFULGLOBALS = 0xf0000044U;
        public const uint CLRTLSDATA_INDEX = 0xf0000045U;
        public const uint MODULE_FINDIL = 0xf0000046U;
        public const uint CLR_WATSON_BUCKETS = 0xf0000047U;
        public const uint OOM_DATA = 0xf0000048U;
        public const uint OOM_STATIC_DATA = 0xf0000049U;
        public const uint GCHEAP_HEAPANALYZE_DATA = 0xf000004aU;
        public const uint GCHEAP_HEAPANALYZE_STATIC_DATA = 0xf000004bU;
        public const uint HANDLETABLE_FILTERED_TRAVERSE = 0xf000004cU;
        public const uint METHODDESC_TRANSPARENCY_DATA = 0xf000004dU;
        public const uint EECLASS_TRANSPARENCY_DATA = 0xf000004eU;
        public const uint THREAD_STACK_BOUNDS = 0xf000004fU;
        public const uint HILL_CLIMBING_LOG_ENTRY = 0xf0000050U;
        public const uint THREADPOOL_DATA_2 = 0xf0000051U;
        public const uint THREADLOCALMODULE_DAT = 0xf0000052U;
    }
    #endregion

#pragma warning disable 0649
#pragma warning disable 0169

    #region Common Dac Structs
    public struct LegacySyncBlkData : ISyncBlkData
    {
        private ulong _pObject;
        private uint _bFree;
        private ulong _syncBlockPointer;
        private uint _COMFlags;
        private uint _bMonitorHeld;
        private uint _nRecursion;
        private ulong _holdingThread;
        private uint _additionalThreadCount;
        private ulong _appDomainPtr;
        private uint _syncBlockCount;

        public bool Free
        {
            get { return _bFree != 0; }
        }

        public ulong Object
        {
            get { return _pObject; }
        }

        public bool MonitorHeld
        {
            get { return _bMonitorHeld != 0; }
        }

        public uint Recursion
        {
            get { return _nRecursion; }
        }

        public uint TotalCount
        {
            get { return _syncBlockCount; }
        }

        public ulong OwningThread
        {
            get { return _holdingThread; }
        }


        public ulong Address
        {
            get { return _syncBlockPointer; }
        }
    }

    // Same for v2 and v4
    [StructLayout(LayoutKind.Sequential)]
    public struct LegacyModuleMapTraverseArgs
    {
        private uint _setToZero;
        public ulong module;
        public IntPtr pCallback;
        public IntPtr token;
    };


    public struct V2MethodDescData : IMethodDescData
    {
        private int _bHasNativeCode;
        private int _bIsDynamic;
        private short _wSlotNumber;
        private ulong _nativeCodeAddr;
        // Useful for breaking when a method is jitted.
        private ulong _addressOfNativeCodeSlot;

        private ulong _methodDescPtr;
        private ulong _methodTablePtr;
        private ulong _EEClassPtr;
        private ulong _modulePtr;

        private ulong _preStubAddr;
        private uint _mdToken;
        private ulong _GCInfo;
        private short _JITType;
        private ulong _GCStressCodeCopy;

        // This is only valid if bIsDynamic is true
        private ulong _managedDynamicMethodObject;

        public ulong MethodDesc
        {
            get { return _methodDescPtr; }
        }

        public ulong Module
        {
            get { return _modulePtr; }
        }

        public uint MDToken
        {
            get { return _mdToken; }
        }


        ulong IMethodDescData.NativeCodeAddr
        {
            get { return _nativeCodeAddr; }
        }

        int IMethodDescData.JITType
        {
            get
            {
                if (_JITType == 1)
                    return (int)MethodCompilationType.Jit;
                else if (_JITType == 2)
                    return (int)MethodCompilationType.Ngen;
                return (int) MethodCompilationType.None;
            }
        }


        public ulong MethodTable
        {
            get { return _methodTablePtr; }
        }

        public ulong GCInfo
        {
            get
            {
                return _GCInfo;
            }
        }

        public ulong ColdStart
        {
            get
            {
                return 0;
            }
        }

        public uint ColdSize
        {
            get
            {
                return 0;
            }
        }

        public uint HotSize
        {
            get
            {
                return 0;
            }
        }
    }

    public struct V35MethodDescData : IMethodDescData
    {
        private int _bHasNativeCode;
        private int _bIsDynamic;
        private short _wSlotNumber;
        private ulong _nativeCodeAddr;
        // Useful for breaking when a method is jitted.
        private ulong _addressOfNativeCodeSlot;

        private ulong _methodDescPtr;
        private ulong _methodTablePtr;
        private ulong _EEClassPtr;
        private ulong _modulePtr;

        private uint _mdToken;
        private ulong _GCInfo;
        private short _JITType;
        private ulong _GCStressCodeCopy;

        // This is only valid if bIsDynamic is true
        private ulong _managedDynamicMethodObject;

        public ulong MethodTable
        {
            get { return _methodTablePtr; }
        }

        public ulong MethodDesc
        {
            get { return _methodDescPtr; }
        }

        public ulong Module
        {
            get { return _modulePtr; }
        }

        public uint MDToken
        {
            get { return _mdToken; }
        }

        public ulong GCInfo
        {
            get
            {
                return _GCInfo;
            }
        }

        ulong IMethodDescData.NativeCodeAddr
        {
            get { return _nativeCodeAddr; }
        }

        int IMethodDescData.JITType
        {
            get
            {
                if (_JITType == 1)
                    return (int)MethodCompilationType.Jit;
                else if (_JITType == 2)
                    return (int)MethodCompilationType.Ngen;
                return (int)MethodCompilationType.None;
            }
        }

        public ulong ColdStart
        {
            get
            {
                return 0;
            }
        }

        public uint ColdSize
        {
            get
            {
                return 0;
            }
        }

        public uint HotSize
        {
            get
            {
                return 0;
            }
        }
    }

    public struct LegacyDomainLocalModuleData : IDomainLocalModuleData
    {
        private ulong _appDomainAddr;
        private IntPtr _moduleID;

        private ulong _pClassData;
        private ulong _pDynamicClassTable;
        private ulong _pGCStaticDataStart;
        private ulong _pNonGCStaticDataStart;

        public ulong AppDomainAddr
        {
            get { return _appDomainAddr; }
        }

        public ulong ModuleID
        {
            get { return (ulong)_moduleID.ToInt64(); }
        }

        public ulong ClassData
        {
            get { return _pClassData; }
        }

        public ulong DynamicClassTable
        {
            get { return _pDynamicClassTable; }
        }

        public ulong GCStaticDataStart
        {
            get { return _pGCStaticDataStart; }
        }

        public ulong NonGCStaticDataStart
        {
            get { return _pNonGCStaticDataStart; }
        }
    }


    public struct LegacyObjectData : IObjectData
    {
        private ulong _eeClass;
        private ulong _methodTable;
        private uint _objectType;
        private uint _size;
        private ulong _elementTypeHandle;
        private uint _elementType;
        private uint _dwRank;
        private uint _dwNumComponents;
        private uint _dwComponentSize;
        private ulong _arrayDataPtr;
        private ulong _arrayBoundsPtr;
        private ulong _arrayLowerBoundsPtr;

        public uint ElementType { get { return _elementType; } }
        public ulong ElementTypeHandle { get { return _elementTypeHandle; } }
        public ulong RCW { get { return 0; } }
        public ulong CCW { get { return 0; } }

        public ulong DataPointer
        {
            get { return _arrayDataPtr; }
        }
    }

    public struct LegacyMethodTableData : IMethodTableData
    {
        public uint bIsFree; // everything else is NULL if this is true.
        public ulong eeClass;
        public ulong parentMethodTable;
        public ushort wNumInterfaces;
        public ushort wNumVtableSlots;
        public uint baseSize;
        public uint componentSize;
        public uint isShared; // flags & enum_flag_DomainNeutral
        public uint sizeofMethodTable;
        public uint isDynamic;
        public uint containsPointers;

        public bool ContainsPointers
        {
            get { return containsPointers != 0; }
        }

        public uint BaseSize
        {
            get { return baseSize; }
        }

        public uint ComponentSize
        {
            get { return componentSize; }
        }

        public ulong EEClass
        {
            get { return eeClass; }
        }

        public bool Free
        {
            get { return bIsFree != 0; }
        }

        public ulong Parent
        {
            get { return parentMethodTable; }
        }

        public bool Shared
        {
            get { return isShared != 0; }
        }


        public uint NumMethods
        {
            get { return wNumVtableSlots; }
        }


        public ulong ElementTypeHandle
        {
            get { throw new NotImplementedException(); }
        }
    }

    // Same for v2 and v4
    public struct LegacyGCInfo : IGCInfo
    {
        public int serverMode;
        public int gcStructuresValid;
        public uint heapCount;
        public uint maxGeneration;

        bool IGCInfo.ServerMode
        {
            get { return serverMode != 0; }
        }

        int IGCInfo.HeapCount
        {
            get { return (int)heapCount; }
        }

        int IGCInfo.MaxGeneration
        {
            get { return (int)maxGeneration; }
        }


        bool IGCInfo.GCStructuresValid
        {
            get { return gcStructuresValid != 0; }
        }
    }

    public struct V4GenerationData
    {
        public ulong StartSegment;
        public ulong AllocationStart;

        // These are examined only for generation 0, otherwise NULL
        public ulong AllocContextPtr;
        public ulong AllocContextLimit;
    }

    public struct LegacyJitCodeHeapInfo : ICodeHeap
    {
        public uint codeHeapType;
        public ulong address;
        public ulong currentAddr;

        public CodeHeapType Type
        {
            get { return (CodeHeapType)codeHeapType; }
        }

        public ulong Address
        {
            get { return address; }
        }
    }

    public struct LegacyJitManagerInfo
    {
        public ulong addr;
        public CodeHeapType type;
        public ulong ptrHeapList;
    }

    // Same for both v2 and v4.
    public struct LegacyAppDomainData : IAppDomainData
    {
        private ulong _address;
        private ulong _appSecDesc;
        private ulong _pLowFrequencyHeap;
        private ulong _pHighFrequencyHeap;
        private ulong _pStubHeap;
        private ulong _pDomainLocalBlock;
        private ulong _pDomainLocalModules;
        private int _dwId;
        private int _assemblyCount;
        private int _failedAssemblyCount;
        private int _appDomainStage;

        public int Id
        {
            get { return _dwId; }
        }

        public ulong Address
        {
            get { return _address; }
        }

        public ulong LowFrequencyHeap { get { return _pLowFrequencyHeap; } }
        public ulong HighFrequencyHeap { get { return _pHighFrequencyHeap; } }
        public ulong StubHeap { get { return _pStubHeap; } }
        public int AssemblyCount
        {
            get { return _assemblyCount; }
        }
    }

    // Same for both v2 and v4.
    public struct LegacyAppDomainStoreData : IAppDomainStoreData
    {
        private ulong _shared;
        private ulong _system;
        private int _domainCount;

        public ulong SharedDomain
        {
            get { return _shared; }
        }

        public ulong SystemDomain
        {
            get { return _system; }
        }

        public int Count
        {
            get { return _domainCount; }
        }
    }

    public struct LegacyAssemblyData : IAssemblyData
    {
        private ulong _assemblyPtr;
        private ulong _classLoader;
        private ulong _parentDomain;
        private ulong _appDomainPtr;
        private ulong _assemblySecDesc;
        private int _isDynamic;
        private int _moduleCount;
        private uint _loadContext;
        private int _isDomainNeutral;
        private uint _dwLocationFlags;

        public ulong Address
        {
            get { return _assemblyPtr; }
        }

        public ulong ParentDomain
        {
            get { return _parentDomain; }
        }

        public ulong AppDomain
        {
            get { return _appDomainPtr; }
        }

        public bool IsDynamic
        {
            get { return _isDynamic != 0; }
        }

        public bool IsDomainNeutral
        {
            get { return _isDomainNeutral != 0; }
        }

        public int ModuleCount
        {
            get { return _moduleCount; }
        }
    }

    public struct LegacyThreadStoreData : IThreadStoreData
    {
        public int threadCount;
        public int unstartedThreadCount;
        public int backgroundThreadCount;
        public int pendingThreadCount;
        public int deadThreadCount;
        public ulong firstThread;
        public ulong finalizerThread;
        public ulong gcThread;
        public uint fHostConfig;          // Uses hosting flags defined above

        public ulong Finalizer
        {
            get { return finalizerThread; }
        }

        public int Count
        {
            get
            {
                return threadCount;
            }
        }

        public ulong FirstThread
        {
            get { return firstThread; }
        }
    }

    public struct LegacyFieldData : IFieldData
    {
        private uint _type;      // CorElementType
        private uint _sigType;   // CorElementType
        private ulong _mtOfType; // NULL if Type is not loaded

        private ulong _moduleOfType;
        private uint _mdType;

        private uint _mdField;
        private ulong _MTOfEnclosingClass;
        private uint _dwOffset;
        private uint _bIsThreadLocal;
        private uint _bIsContextLocal;
        private uint _bIsStatic;
        private ulong _nextField;

        public uint CorElementType
        {
            get { return _type; }
        }

        public uint SigType
        {
            get { return _sigType; }
        }

        public ulong TypeMethodTable
        {
            get { return _mtOfType; }
        }

        public ulong Module
        {
            get { return _moduleOfType; }
        }

        public uint TypeToken
        {
            get { return _mdType; }
        }

        public uint FieldToken
        {
            get { return _mdField; }
        }

        public ulong EnclosingMethodTable
        {
            get { return _MTOfEnclosingClass; }
        }

        public uint Offset
        {
            get { return _dwOffset; }
        }

        public bool IsThreadLocal
        {
            get { return _bIsThreadLocal != 0; }
        }

        bool IFieldData.IsContextLocal
        {
            get { return _bIsContextLocal != 0; }
        }

        bool IFieldData.IsStatic
        {
            get { return _bIsStatic != 0; }
        }

        ulong IFieldData.NextField
        {
            get { return _nextField; }
        }
    }
    #endregion

    #region V2 Dac Data Structs


    public enum WorkRequestFunctionTypes
    {
        QUEUEUSERWORKITEM,
        TIMERDELETEWORKITEM,
        ASYNCCALLBACKCOMPLETION,
        ASYNCTIMERCALLBACKCOMPLETION,
        UNKNOWNWORKITEM
    }
    public struct DacpWorkRequestData
    {
        public WorkRequestFunctionTypes FunctionType;
        public ulong Function;
        public ulong Context;
        public ulong NextWorkRequest;
    }

    public struct V2ThreadPoolData : IThreadPoolData
    {
        private int _cpuUtilization;
        private int _numWorkerThreads;
        private int _minLimitTotalWorkerThreads;
        private int _maxLimitTotalWorkerThreads;
        private int _numRunningWorkerThreads;
        private int _numIdleWorkerThreads;
        private int _numQueuedWorkRequests;

        private ulong _firstWorkRequest;

        private uint _numTimers;

        private int _numCPThreads;
        private int _numFreeCPThreads;
        private int _maxFreeCPThreads;
        private int _numRetiredCPThreads;
        private int _maxLimitTotalCPThreads;
        private int _currentLimitTotalCPThreads;
        private int _minLimitTotalCPThreads;

        private ulong _QueueUserWorkItemCallbackFPtr;
        private ulong _AsyncCallbackCompletionFPtr;
        private ulong _AsyncTimerCallbackCompletionFPtr;



        public int MinCP
        {
            get { return _minLimitTotalCPThreads; }
        }

        public int MaxCP
        {
            get { return _maxLimitTotalCPThreads; }
        }

        public int CPU
        {
            get { return _cpuUtilization; }
        }

        public int NumFreeCP
        {
            get { return _numFreeCPThreads; }
        }

        public int MaxFreeCP
        {
            get { return _maxFreeCPThreads; }
        }

        public int TotalThreads
        {
            get { return _numWorkerThreads; }
        }

        public int RunningThreads
        {
            get { return _numRunningWorkerThreads; }
        }

        public int IdleThreads
        {
            get { return _numIdleWorkerThreads; }
        }

        public int MinThreads
        {
            get { return _minLimitTotalWorkerThreads; }
        }

        public int MaxThreads
        {
            get { return _maxLimitTotalWorkerThreads; }
        }


        ulong IThreadPoolData.FirstWorkRequest
        {
            get { return _firstWorkRequest; }
        }


        public ulong QueueUserWorkItemCallbackFPtr
        {
            get { return _QueueUserWorkItemCallbackFPtr; }
        }

        public ulong AsyncCallbackCompletionFPtr
        {
            get { return _AsyncCallbackCompletionFPtr; }
        }

        public ulong AsyncTimerCallbackCompletionFPtr
        {
            get { return _AsyncTimerCallbackCompletionFPtr; }
        }
    }

    public struct V2ModuleData : IModuleData
    {
        public ulong peFile;
        public ulong ilBase;
        public ulong metadataStart;
        public IntPtr metadataSize;
        public ulong assembly;
        public uint bIsReflection;
        public uint bIsPEFile;
        public IntPtr dwBaseClassIndex;
        [MarshalAs(UnmanagedType.IUnknown)]
        public object ModuleDefinition;
        public IntPtr dwDomainNeutralIndex;

        public uint dwTransientFlags;

        public ulong TypeDefToMethodTableMap;
        public ulong TypeRefToMethodTableMap;
        public ulong MethodDefToDescMap;
        public ulong FieldDefToDescMap;
        public ulong MemberRefToDescMap;
        public ulong FileReferencesMap;
        public ulong ManifestModuleReferencesMap;

        public ulong pLookupTableHeap;
        public ulong pThunkHeap;

        public ulong Assembly
        {
            get
            {
                return assembly;
            }
        }

        public ulong ImageBase
        {
            get
            {
                return ilBase;
            }
        }

        public ulong PEFile
        {
            get { return peFile; }
        }

        public ulong LookupTableHeap
        {
            get { return pLookupTableHeap; }
        }

        public ulong ThunkHeap
        {
            get { return pThunkHeap; }
        }


        public object LegacyMetaDataImport
        {
            get { return ModuleDefinition; }
        }


        public ulong ModuleId
        {
            get { return (ulong)dwDomainNeutralIndex.ToInt64(); }
        }


        public ulong ModuleIndex
        {
            get { return 0; }
        }

        public bool IsReflection
        {
            get { return bIsReflection != 0; }
        }

        public bool IsPEFile
        {
            get { return bIsPEFile != 0; }
        }


        public ulong MetdataStart
        {
            get { return metadataStart; }
        }

        public ulong MetadataLength
        {
            get { return (ulong)metadataSize.ToInt64(); }
        }
    }

    public struct V2EEClassData : IEEClassData, IFieldInfo
    {
        public ulong methodTable;
        public ulong module;
        public short wNumVtableSlots;
        public short wNumMethodSlots;
        public short wNumInstanceFields;
        public short wNumStaticFields;
        public uint dwClassDomainNeutralIndex;
        public uint dwAttrClass; // cached metadata
        public uint token; // Metadata token

        public ulong addrFirstField; // If non-null, you can retrieve more

        public short wThreadStaticOffset;
        public short wThreadStaticsSize;
        public short wContextStaticOffset;
        public short wContextStaticsSize;

        public ulong Module
        {
            get { return module; }
        }

        public ulong MethodTable
        {
            get { return methodTable; }
        }

        public uint InstanceFields
        {
            get { return (uint)wNumInstanceFields; }
        }

        public uint StaticFields
        {
            get { return (uint)wNumStaticFields; }
        }

        public uint ThreadStaticFields
        {
            get { return (uint)0; }
        }

        public ulong FirstField
        {
            get { return (ulong)addrFirstField; }
        }
    }

    public struct V2ThreadData : IThreadData
    {
        public uint corThreadId;
        public uint osThreadId;
        public int state;
        public uint preemptiveGCDisabled;
        public ulong allocContextPtr;
        public ulong allocContextLimit;
        public ulong context;
        public ulong domain;
        public ulong sharedStaticData;
        public ulong unsharedStaticData;
        public ulong pFrame;
        public uint lockCount;
        public ulong firstNestedException;
        public ulong teb;
        public ulong fiberData;
        public ulong lastThrownObjectHandle;
        public ulong nextThread;

        public ulong Next
        {
            get { return IntPtr.Size == 8 ? nextThread : (ulong)(uint)nextThread; }
        }

        public ulong AllocPtr
        {
            get { return (IntPtr.Size == 8) ? allocContextPtr : (ulong)(uint)allocContextPtr; }
        }

        public ulong AllocLimit
        {
            get { return (IntPtr.Size == 8) ? allocContextLimit : (ulong)(uint)allocContextLimit; }
        }


        public uint OSThreadID
        {
            get { return osThreadId; }
        }

        public ulong Teb
        {
            get { return IntPtr.Size == 8 ? teb : (ulong)(uint)teb; }
        }


        public ulong AppDomain
        {
            get { return domain; }
        }

        public uint LockCount
        {
            get { return lockCount; }
        }

        public int State
        {
            get { return state; }
        }


        public ulong ExceptionPtr
        {
            get { return lastThrownObjectHandle; }
        }

        public uint ManagedThreadID
        {
            get { return corThreadId; }
        }


        public bool Preemptive
        {
            get { return preemptiveGCDisabled == 0; }
        }
    }


    public struct V2SegmentData : ISegmentData
    {
        public ulong segmentAddr;
        public ulong allocated;
        public ulong committed;
        public ulong reserved;
        public ulong used;
        public ulong mem;
        public ulong next;
        public ulong gc_heap;
        public ulong highAllocMark;

        public ulong Address
        {
            get { return segmentAddr; }
        }

        public ulong Next
        {
            get { return next; }
        }

        public ulong Start
        {
            get { return mem; }
        }

        public ulong End
        {
            get { return allocated; }
        }

        public ulong Reserved
        {
            get { return reserved; }
        }

        public ulong Committed
        {
            get { return committed; }
        }
    }


    public struct V2HeapDetails : IHeapDetails
    {
        public ulong heapAddr;
        public ulong alloc_allocated;

        public V4GenerationData generation_table0;
        public V4GenerationData generation_table1;
        public V4GenerationData generation_table2;
        public V4GenerationData generation_table3;
        public ulong ephemeral_heap_segment;
        public ulong finalization_fill_pointers0;
        public ulong finalization_fill_pointers1;
        public ulong finalization_fill_pointers2;
        public ulong finalization_fill_pointers3;
        public ulong finalization_fill_pointers4;
        public ulong finalization_fill_pointers5;
        public ulong lowest_address;
        public ulong highest_address;
        public ulong card_table;

        public ulong FirstHeapSegment
        {
            get { return generation_table2.StartSegment; }
        }

        public ulong FirstLargeHeapSegment
        {
            get { return generation_table3.StartSegment; }
        }

        public ulong EphemeralSegment
        {
            get { return ephemeral_heap_segment; }
        }

        public ulong EphemeralEnd { get { return alloc_allocated; } }


        public ulong EphemeralAllocContextPtr
        {
            get { return generation_table0.AllocContextPtr; }
        }

        public ulong EphemeralAllocContextLimit
        {
            get { return generation_table0.AllocContextLimit; }
        }


        public ulong FQAllObjectsStop
        {
            get { return finalization_fill_pointers5; }
        }

        public ulong FQAllObjectsStart
        {
            get { return finalization_fill_pointers3; }
        }

        public ulong FQRootsStart
        {
            get { return finalization_fill_pointers0; }
        }

        public ulong FQRootsEnd
        {
            get { return finalization_fill_pointers3; }
        }

        public ulong Gen0Start
        {
            get { return generation_table0.AllocationStart; }
        }

        public ulong Gen0Stop
        {
            get { return alloc_allocated; }
        }

        public ulong Gen1Start
        {
            get { return generation_table1.AllocationStart; }
        }

        public ulong Gen1Stop
        {
            get { return generation_table0.AllocationStart; }
        }

        public ulong Gen2Start
        {
            get { return generation_table2.AllocationStart; }
        }

        public ulong Gen2Stop
        {
            get { return generation_table1.AllocationStart; }
        }
    }

    #endregion

    #region V4 Dac Data Structs
    public struct V4ThreadPoolData : IThreadPoolData
    {
        private uint _useNewWorkerPool;

        private int _cpuUtilization;
        private int _numIdleWorkerThreads;
        private int _numWorkingWorkerThreads;
        private int _numRetiredWorkerThreads;
        private int _minLimitTotalWorkerThreads;
        private int _maxLimitTotalWorkerThreads;

        private ulong _firstUnmanagedWorkRequest;

        private ulong _hillClimbingLog;
        private int _hillClimbingLogFirstIndex;
        private int _hillClimbingLogSize;

        private uint _numTimers;

        private int _numCPThreads;
        private int _numFreeCPThreads;
        private int _maxFreeCPThreads;
        private int _numRetiredCPThreads;
        private int _maxLimitTotalCPThreads;
        private int _currentLimitTotalCPThreads;
        private int _minLimitTotalCPThreads;

        private ulong _queueUserWorkItemCallbackFPtr;
        private ulong _asyncCallbackCompletionFPtr;
        private ulong _asyncTimerCallbackCompletionFPtr;


        public int MinCP
        {
            get { return _minLimitTotalCPThreads; }
        }

        public int MaxCP
        {
            get { return _maxLimitTotalCPThreads; }
        }

        public int CPU
        {
            get { return _cpuUtilization; }
        }

        public int NumFreeCP
        {
            get { return _numFreeCPThreads; }
        }

        public int MaxFreeCP
        {
            get { return _maxFreeCPThreads; }
        }

        public int TotalThreads
        {
            get { return _numWorkingWorkerThreads; }
        }

        public int RunningThreads
        {
            get { return _numWorkingWorkerThreads + _numIdleWorkerThreads + _numRetiredWorkerThreads; }
        }

        public int IdleThreads
        {
            get { return _numIdleWorkerThreads; }
        }

        public int MinThreads
        {
            get { return _minLimitTotalWorkerThreads; }
        }

        public int MaxThreads
        {
            get { return _maxLimitTotalWorkerThreads; }
        }


        public ulong FirstWorkRequest
        {
            get { return _firstUnmanagedWorkRequest; }
        }


        ulong IThreadPoolData.QueueUserWorkItemCallbackFPtr
        {
            get { return ulong.MaxValue; }
        }

        ulong IThreadPoolData.AsyncCallbackCompletionFPtr
        {
            get { return ulong.MaxValue; }
        }

        ulong IThreadPoolData.AsyncTimerCallbackCompletionFPtr
        {
            get { return ulong.MaxValue; }
        }
    }

    public struct V4EEClassData : IEEClassData, IFieldInfo
    {
        public ulong methodTable;
        public ulong module;
        public short wNumVtableSlots;
        public short wNumMethodSlots;
        public short wNumInstanceFields;
        public short wNumStaticFields;
        public short wNumThreadStaticFields;
        public uint dwClassDomainNeutralIndex;
        public uint dwAttrClass; // cached metadata
        public uint token; // Metadata token

        public ulong addrFirstField; // If non-null, you can retrieve more

        public short wContextStaticOffset;
        public short wContextStaticsSize;

        public ulong Module
        {
            get { return module; }
        }

        ulong IEEClassData.MethodTable
        {
            get { return methodTable; }
        }

        public uint InstanceFields
        {
            get { return (uint)wNumInstanceFields; }
        }

        public uint StaticFields
        {
            get { return (uint)wNumStaticFields; }
        }

        public uint ThreadStaticFields
        {
            get { return (uint)0; }
        }

        public ulong FirstField
        {
            get { return addrFirstField; }
        }
    }

    public struct V4ModuleData : IModuleData
    {
        public ulong peFile;
        public ulong ilBase;
        public ulong metadataStart;
        public IntPtr metadataSize;
        public ulong assembly;
        public uint bIsReflection;
        public uint bIsPEFile;
        public IntPtr dwBaseClassIndex;
        [MarshalAs(UnmanagedType.IUnknown)]
        public object ModuleDefinition;
        public IntPtr dwModuleID;

        public uint dwTransientFlags;

        public ulong TypeDefToMethodTableMap;
        public ulong TypeRefToMethodTableMap;
        public ulong MethodDefToDescMap;
        public ulong FieldDefToDescMap;
        public ulong MemberRefToDescMap;
        public ulong FileReferencesMap;
        public ulong ManifestModuleReferencesMap;

        public ulong pLookupTableHeap;
        public ulong pThunkHeap;

        public IntPtr dwModuleIndex;

        public ulong PEFile
        {
            get { return peFile; }
        }

        public ulong Assembly
        {
            get
            {
                return assembly;
            }
        }

        public ulong ImageBase
        {
            get { return ilBase; }
        }

        public ulong LookupTableHeap
        {
            get { return pLookupTableHeap; }
        }

        public ulong ThunkHeap
        {
            get { return pThunkHeap; }
        }


        public object LegacyMetaDataImport
        {
            get { return ModuleDefinition; }
        }


        public ulong ModuleId
        {
            get { return (ulong)dwModuleID.ToInt64(); }
        }

        public ulong ModuleIndex
        {
            get { return (ulong)dwModuleIndex.ToInt64(); }
        }

        public bool IsReflection
        {
            get { return bIsReflection != 0; }
        }

        public bool IsPEFile
        {
            get { return bIsPEFile != 0; }
        }


        public ulong MetdataStart
        {
            get { return metadataStart; }
        }

        public ulong MetadataLength
        {
            get { return (ulong)metadataSize.ToInt64(); }
        }
    }


    public struct V4ThreadData : IThreadData
    {
        public uint corThreadId;
        public uint osThreadId;
        public int state;
        public uint preemptiveGCDisabled;
        public ulong allocContextPtr;
        public ulong allocContextLimit;
        public ulong context;
        public ulong domain;
        public ulong pFrame;
        public uint lockCount;
        public ulong firstNestedException;
        public ulong teb;
        public ulong fiberData;
        public ulong lastThrownObjectHandle;
        public ulong nextThread;

        public ulong Next
        {
            get { return IntPtr.Size == 8 ? nextThread : (ulong)(uint)nextThread; }
        }

        public ulong AllocPtr
        {
            get { return (IntPtr.Size == 8) ? allocContextPtr : (ulong)(uint)allocContextPtr; }
        }

        public ulong AllocLimit
        {
            get { return (IntPtr.Size == 8) ? allocContextLimit : (ulong)(uint)allocContextLimit; }
        }


        public uint OSThreadID
        {
            get { return osThreadId; }
        }

        public ulong Teb
        {
            get { return IntPtr.Size == 8 ? teb : (ulong)(uint)teb; }
        }


        public ulong AppDomain
        {
            get { return domain; }
        }

        public uint LockCount
        {
            get { return lockCount; }
        }

        public int State
        {
            get { return state; }
        }

        public ulong ExceptionPtr
        {
            get { return lastThrownObjectHandle; }
        }


        public uint ManagedThreadID
        {
            get { return corThreadId; }
        }


        public bool Preemptive
        {
            get { return preemptiveGCDisabled == 0; }
        }
    }

    public struct V45AllocData
    {
        public ulong allocBytes;
        public ulong allocBytesLoh;
    }

    public struct V45GenerationAllocData
    {
        public ulong allocBytesGen0;
        public ulong allocBytesLohGen0;
        public ulong allocBytesGen1;
        public ulong allocBytesLohGen1;
        public ulong allocBytesGen2;
        public ulong allocBytesLohGen2;
        public ulong allocBytesGen3;
        public ulong allocBytesLohGen3;
    }

    public struct V4FieldInfo : IFieldInfo
    {
        private short _wNumInstanceFields;
        private short _wNumStaticFields;
        private short _wNumThreadStaticFields;

        private ulong _addrFirstField; // If non-null, you can retrieve more

        private short _wContextStaticOffset;
        private short _wContextStaticsSize;

        public uint InstanceFields
        {
            get { return (uint)_wNumInstanceFields; }
        }

        public uint StaticFields
        {
            get { return (uint)_wNumStaticFields; }
        }

        public uint ThreadStaticFields
        {
            get { return (uint)_wNumThreadStaticFields; }
        }

        public ulong FirstField
        {
            get { return _addrFirstField; }
        }
    }

    public struct V4SegmentData : ISegmentData
    {
        public ulong segmentAddr;
        public ulong allocated;
        public ulong committed;
        public ulong reserved;
        public ulong used;
        public ulong mem;
        public ulong next;
        public ulong gc_heap;
        public ulong highAllocMark;
        public IntPtr flags;
        public ulong background_allocated;

        public ulong Address
        {
            get { return segmentAddr; }
        }

        public ulong Next
        {
            get { return next; }
        }

        public ulong Start
        {
            get { return mem; }
        }

        public ulong End
        {
            get { return allocated; }
        }

        public ulong Reserved
        {
            get { return reserved; }
        }

        public ulong Committed
        {
            get { return committed; }
        }
    }

    public struct V4HeapDetails : IHeapDetails
    {
        public ulong heapAddr; // Only filled in in server mode, otherwise NULL

        public ulong alloc_allocated;
        public ulong mark_array;
        public ulong c_allocate_lh;
        public ulong next_sweep_obj;
        public ulong saved_sweep_ephemeral_seg;
        public ulong saved_sweep_ephemeral_start;
        public ulong background_saved_lowest_address;
        public ulong background_saved_highest_address;

        public V4GenerationData generation_table0;
        public V4GenerationData generation_table1;
        public V4GenerationData generation_table2;
        public V4GenerationData generation_table3;
        public ulong ephemeral_heap_segment;
        public ulong finalization_fill_pointers0;
        public ulong finalization_fill_pointers1;
        public ulong finalization_fill_pointers2;
        public ulong finalization_fill_pointers3;
        public ulong finalization_fill_pointers4;
        public ulong finalization_fill_pointers5;
        public ulong finalization_fill_pointers6;
        public ulong lowest_address;
        public ulong highest_address;
        public ulong card_table;

        public ulong FirstHeapSegment
        {
            get { return generation_table2.StartSegment; }
        }

        public ulong FirstLargeHeapSegment
        {
            get { return generation_table3.StartSegment; }
        }

        public ulong EphemeralSegment
        {
            get { return ephemeral_heap_segment; }
        }

        public ulong EphemeralEnd { get { return alloc_allocated; } }


        public ulong EphemeralAllocContextPtr
        {
            get { return generation_table0.AllocContextPtr; }
        }

        public ulong EphemeralAllocContextLimit
        {
            get { return generation_table0.AllocContextLimit; }
        }
        public ulong FQAllObjectsStart
        {
            get { return finalization_fill_pointers0; }
        }

        public ulong FQAllObjectsStop
        {
            get { return finalization_fill_pointers3; }
        }


        public ulong FQRootsStart
        {
            get { return finalization_fill_pointers3; }
        }

        public ulong FQRootsEnd
        {
            get { return finalization_fill_pointers6; }
        }

        public ulong Gen0Start
        {
            get { return generation_table0.AllocationStart; }
        }

        public ulong Gen0Stop
        {
            get { return alloc_allocated; }
        }

        public ulong Gen1Start
        {
            get { return generation_table1.AllocationStart; }
        }

        public ulong Gen1Stop
        {
            get { return generation_table0.AllocationStart; }
        }

        public ulong Gen2Start
        {
            get { return generation_table2.AllocationStart; }
        }

        public ulong Gen2Stop
        {
            get { return generation_table1.AllocationStart; }
        }
    }
    #endregion

#pragma warning restore 0169
#pragma warning restore 0649
}
