//go:build windows

// Copyright 2026 CrabCanneryShip
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package privilege handles UAC self-elevation and Windows-specific privilege management.
package privilege

import (
	"fmt"
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

// EnableBackupPrivilege enables backup and security-related privileges on the current process token.
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

// enablePrivilege enables a specified privilege on the provided process token.
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
