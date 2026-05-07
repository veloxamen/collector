//go:build windows

// Package privilege handles UAC self-elevation and Windows-specific privilege management.
package privilege

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// IsAdmin checks if the current process is running with administrative privileges.
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY, 2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

// RelaunchElevated attempts to re-launch the current executable with the "runas" verb.
func RelaunchElevated() error {
	verb, _ := syscall.UTF16PtrFromString("runas")
	exe, _ := syscall.UTF16PtrFromString(os.Args[0])
	argStr := buildArgString(os.Args[1:])
	argPtr, _ := syscall.UTF16PtrFromString(argStr)

	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExec := shell32.NewProc("ShellExecuteW")
	r, _, _ := shellExec.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(exe)),
		uintptr(unsafe.Pointer(argPtr)),
		0,
		1, // SW_SHOWNORMAL
	)
	if r <= 32 {
		return fmt.Errorf("ShellExecuteW returned %d", r)
	}
	return nil
}

// buildArgString escapes and joins command-line arguments.
func EnableBackupPrivilege() error {
	privs := []string{
		"SeBackupPrivilege",
		"SeSecurityPrivilege",
		"SeRestorePrivilege",
	}
	var token windows.Token
	proc := windows.CurrentProcess()
	if err := windows.OpenProcessToken(proc,
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("OpenProcessToken failed: %w", err)
	}
	defer token.Close()

	for _, name := range privs {
		if err := enablePrivilege(token, name); err != nil {
			fmt.Printf("[!] Skipping %s: %v\n", name, err)
		}
	}
	return nil
}

// EnableBackupPrivilege enables SeBackupPrivilege on the current process token.
func enablePrivilege(token windows.Token, name string) error {
	var luid windows.LUID
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp,
		uint32(unsafe.Sizeof(tp)), nil, nil)
}

// EnableDebugPrivilege enables SeDebugPrivilege on the current process token.
func EnableDebugPrivilege() error {
	return enableNamedPrivilege("SeDebugPrivilege")
}

// enableNamedPrivilege looks up and enables a specific Windows privilege by name.
func enableNamedPrivilege(name string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	namePtr, _ := windows.UTF16PtrFromString(name)
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, err)
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp,
		uint32(unsafe.Sizeof(tp)), nil, nil)
}

// buildArgString concatenates strings to make command arguments for a new console.
func buildArgString(args []string) string {
	var sb strings.Builder
	for i, a := range args {
		if i > 0 {
			sb.WriteByte(' ')
		}
		if strings.ContainsAny(a, " \t") {
			sb.WriteByte('"')
			sb.WriteString(a)
			sb.WriteByte('"')
		} else {
			sb.WriteString(a)
		}
	}
	return sb.String()
}
