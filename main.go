package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/itchio/ox/syscallex"
)

func main() {
	log.Printf("Loading debug privileges...")
	loadDebugPrivileges()
	log.Printf("Done!")

	if len(os.Args) < 2 {
		log.Fatalf("Usage: %s DLL EXE", os.Args[0])
	}

	// dllFile, exeFile := os.Args[1], os.Args[2]
	// injectExe(dllFile, exeFile)

	dllFile, pidString := os.Args[1], os.Args[2]
	pid, err := strconv.ParseInt(pidString, 10, 64)
	must(err)
	injectPID(dllFile, pid)
}

func loadDebugPrivileges() {
	var token syscall.Token
	currentProcess, err := syscall.GetCurrentProcess()
	must(err)

	var flags uint32 = syscallex.TOKEN_ADJUST_PRIVILEGES | syscall.TOKEN_QUERY
	must(syscall.OpenProcessToken(currentProcess, flags, &token))
	defer token.Close()

	var val syscallex.LUID

	must(syscallex.LookupPrivilegeValue(nil, syscallex.SE_DEBUG_NAME, &val))
	var tp syscallex.TOKEN_PRIVILEGES
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid = val
	tp.Privileges[0].Attributes = syscallex.SE_PRIVILEGE_ENABLED

	_, err = syscallex.AdjustTokenPrivileges(token, false, &tp, uint32(unsafe.Sizeof(tp)), nil, nil)
	if err != nil {
		log.Printf("Warning: AdjustTokenPrileges failed: %v", err)
	}
	/*err = enableAllPrivileges(token)
	if err != nil {
		log.Printf("Warning: AdjustTokenPrileges failed: %v", err)
	}*/
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}

func enableAllPrivileges(token syscall.Token) error {
	privileges := []string{
		"SeCreateTokenPrivilege",
		"SeAssignPrimaryTokenPrivilege",
		"SeLockMemoryPrivilege",
		"SeIncreaseQuotaPrivilege",
		"SeMachineAccountPrivilege",
		"SeTcbPrivilege",
		"SeSecurityPrivilege",
		"SeTakeOwnershipPrivilege",
		"SeLoadDriverPrivilege",
		"SeSystemProfilePrivilege",
		"SeSystemtimePrivilege",
		"SeProfileSingleProcessPrivilege",
		"SeIncreaseBasePriorityPrivilege",
		"SeCreatePagefilePrivilege",
		"SeCreatePermanentPrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeShutdownPrivilege",
		"SeDebugPrivilege",
		"SeAuditPrivilege",
		"SeSystemEnvironmentPrivilege",
		"SeChangeNotifyPrivilege",
		"SeRemoteShutdownPrivilege",
		"SeUndockPrivilege",
		"SeSyncAgentPrivilege",
		"SeEnableDelegationPrivilege",
		"SeManageVolumePrivilege",
		"SeImpersonatePrivilege",
		"SeCreateGlobalPrivilege",
		"SeTrustedCredManAccessPrivilege",
		"SeRelabelPrivilege",
		"SeIncreaseWorkingSetPrivilege",
		"SeTimeZonePrivilege",
		"SeCreateSymbolicLinkPrivilege",
	}

	for _, privilege := range privileges {
		err := EnablePrivilege(token, privilege)
		if err != nil {
			return err
		}
	}
	return nil
}

func EnablePrivilege(token syscall.Token, privilege string) error {
	uid, err := lookupPrivilegeValue("", privilege)
	if err != nil {
		return err
	}

	return adjustTokenPrivileges(token, *uid)
}

type DWord uint32

type luid struct {
	lowPart  uint32
	highPart uint32
}

type luidAndAttributes struct {
	luid       luid
	attributes DWord
}

type tokenPrivileges struct {
	privilegeCount DWord
	privileges     *luidAndAttributes
}

const sePrivilegeEnabled = DWord(0x00000002)

var dlls map[string]*syscall.DLL

func loadDLL(name string) (dll *syscall.DLL, err error) {
	if dlls == nil {
		dlls = make(map[string]*syscall.DLL)
	}

	dll, exists := dlls[name]
	if !exists {
		dll, err = syscall.LoadDLL(name)
		if err != nil {
			return
		}
		dlls[name] = dll
	}
	return
}

func loadProc(dllName string, procName string) (*syscall.Proc, error) {
	dll, err := loadDLL(dllName)
	if err != nil {
		return nil, err
	}
	return dll.FindProc(procName)
}
func lookupPrivilegeValue(systemName string, name string) (*luid, error) {
	proc, err := loadProc("advapi32.dll", "LookupPrivilegeValueW")
	if err != nil {
		return nil, err
	}

	l := luid{}

	wsSystemName := uintptr(0)
	if len(systemName) > 0 {
		wsSystemName = uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(systemName)))
	}

	r1, _, err := proc.Call(
		wsSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(&l)),
	)
	if r1 == 1 {
		return &l, nil
	}
	return nil, err
}

func adjustTokenPrivileges(token syscall.Token, uid luid) error {
	proc, err := loadProc("advapi32.dll", "AdjustTokenPrivileges")
	if err != nil {
		return err
	}

	newState := tokenPrivileges{
		privilegeCount: 1,
		privileges: &luidAndAttributes{
			luid:       uid,
			attributes: sePrivilegeEnabled,
		},
	}

	r1, _, err := proc.Call(
		uintptr(token),
		uintptr(0),
		uintptr(unsafe.Pointer(&newState)),
		uintptr(unsafe.Sizeof(newState)),
		uintptr(0),
		uintptr(0),
	)
	if r1 == 1 {
		return nil
	}
	return err
}
