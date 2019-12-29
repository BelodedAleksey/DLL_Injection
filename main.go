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
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("%+v", err))
	}
}
