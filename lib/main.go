package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/castaneai/hinako"
	"github.com/nanitefactory/winmb"
	"github.com/zetamatta/go-outputdebug"
)

import "C"

//export Test
func Test() {
	winmb.MessageBoxPlain("export Test", "export Test")
}

var hook *hinako.Hook

const (
	SystemBasicInformation                  = 0
	SystemPerformanceInformation            = 2
	SystemTimeOfDayInformation              = 3
	SystemProcessInformation                = 5
	SystemProcessorPerformanceInformation   = 8
	SystemInterruptInformation              = 23
	SystemExceptionInformation              = 33
	SystemRegistryQuotaInformation          = 37
	SystemLookasideInformation              = 45
	SystemProcessorIdleCycleTimeInformation = 83
	SystemProcessorCycleTimeInformation     = 108
	SystemPolicyInformation                 = 134

	// size of systemProcessInfoSize in memory
	systemProcessInfoSize = unsafe.Sizeof(systemProcessInformation{})
)

type systemProcessorPerformanceInformation struct {
	IdleTime       int64 // idle time in 100ns (this is not a filetime).
	KernelTime     int64 // kernel time in 100ns.  kernel time includes idle time. (this is not a filetime).
	UserTime       int64 // usertime in 100ns (this is not a filetime).
	DpcTime        int64 // dpc time in 100ns (this is not a filetime).
	InterruptTime  int64 // interrupt time in 100ns
	InterruptCount uint32
}

// KPRIORITY
type kPriority int32

// UNICODE_STRING
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	BufferAddr    *uint16
}

// SYSTEM_PROCESS_INFORMATION
type systemProcessInformation struct {
	NextEntryOffset              uint32        // ULONG
	NumberOfThreads              uint32        // ULONG
	WorkingSetPrivateSize        int64         // LARGE_INTEGER
	HardFaultCount               uint32        // ULONG
	NumberOfThreadsHighWatermark uint32        // ULONG
	CycleTime                    uint64        // ULONGLONG
	CreateTime                   int64         // LARGE_INTEGER
	UserTime                     int64         // LARGE_INTEGER
	KernelTime                   int64         // LARGE_INTEGER
	ImageName                    unicodeString // UNICODE_STRING
	BasePriority                 kPriority     // KPRIORITY
	UniqueProcessID              uintptr       // HANDLE
	InheritedFromUniqueProcessID uintptr       // HANDLE
	HandleCount                  uint32        // ULONG
	SessionID                    uint32        // ULONG
	UniqueProcessKey             *uint32       // ULONG_PTR
	PeakVirtualSize              uintptr       // SIZE_T
	VirtualSize                  uintptr       // SIZE_T
	PageFaultCount               uint32        // ULONG
	PeakWorkingSetSize           uintptr       // SIZE_T
	WorkingSetSize               uintptr       // SIZE_T
	QuotaPeakPagedPoolUsage      uintptr       // SIZE_T
	QuotaPagedPoolUsage          uintptr       // SIZE_T
	QuotaPeakNonPagedPoolUsage   uintptr       // SIZE_T
	QuotaNonPagedPoolUsage       uintptr       // SIZE_T
	PagefileUsage                uintptr       // SIZE_T
	PeakPagefileUsage            uintptr       // SIZE_T
	PrivatePageCount             uintptr       // SIZE_T
	ReadOperationCount           int64         // LARGE_INTEGER
	WriteOperationCount          int64         // LARGE_INTEGER
	OtherOperationCount          int64         // LARGE_INTEGER
	ReadTransferCount            int64         // LARGE_INTEGER
	WriteTransferCount           int64         // LARGE_INTEGER
	OtherTransferCount           int64         // LARGE_INTEGER
}

// OnProcessAttach is an async callback (hook).
//export OnProcessAttach
func OnProcessAttach(
	hinstDLL unsafe.Pointer, // handle to DLL module
	fdwReason uint32, // reason for calling function
	lpReserved unsafe.Pointer, // reserved
) {
	winmb.MessageBoxPlain("OnProcessAttach", "OnProcessAttach")
	// API Hooking by hinako
	arch, err := hinako.NewRuntimeArch()
	if err != nil {
		outputdebug.String(fmt.Sprintf("NewRunTimeArch failed: %s", err.Error()))
	}
	var originalNtQuerySystemInformation *syscall.Proc = nil
	/*hook, err = hinako.NewHookByName(arch, "user32.dll", "MessageBoxW", func(hWnd syscall.Handle, lpText, lpCaption *uint16, uType uint) int {
		r, _, _ := originalMessageBoxW.Call(uintptr(hWnd), WSTRPtr("Hooked!"), WSTRPtr("Hooked!"), uintptr(uType))
		return int(r)
	})*/
	hook, err = hinako.NewHookByName(arch, "ntdll.dll", "NtQuerySystemInformation", func(SystemInformationClass uint32, SystemInformation uintptr, SystemInformationLength uint32, ReturnLength *uint32) int {
		//winmb.MessageBoxPlain("HOOK!", "HOOK!")

		// Make maxResults large for safety.
		// We can't invoke the api call with a results array that's too small.
		// If we have more than 2056 cores on a single host, then it's probably the future.
		maxBuffer := 2056
		// buffer for results from the windows proc
		resultBuffer := make([]systemProcessInformation, maxBuffer)
		// size of the buffer in memory
		bufferSize := uintptr(systemProcessInfoSize) * uintptr(maxBuffer)
		// size of the returned response
		var retSize uint32
		retCode, _, err := originalNtQuerySystemInformation.Call(
			SystemProcessInformation,                  // System Information Class
			uintptr(unsafe.Pointer(&resultBuffer[0])), // pointer to first element in result buffer
			bufferSize,                        // size of the buffer in memory
			uintptr(unsafe.Pointer(&retSize)), // pointer to the size of the returned results the windows proc will set this
		)
		if retCode != 0 {
			outputdebug.String(fmt.Sprintf("NtQuerySystemInformation failed: %s , RetCode: %d", err.Error(), int(retCode)))
		}
		return int(retCode)
	})
	if err != nil {
		outputdebug.String(fmt.Sprintf("hook failed: %s", err.Error()))
	}
	originalNtQuerySystemInformation = hook.OriginalProc
}

// OnProcessDetach is an async callback (hook).
//export OnProcessDetach
func OnProcessDetach() {
	winmb.MessageBoxPlain("OnProcessDetach", "OnProcessDetach")
	defer hook.Close()
}

const title = "TITLE"

var version = "undefined"

//export WSTRPtr
func WSTRPtr(str string) uintptr {
	ptr, _ := syscall.UTF16PtrFromString(str)
	return uintptr(unsafe.Pointer(ptr))
}

func main() {

}
