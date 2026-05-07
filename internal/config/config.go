//go:build windows

// Package config provides functionality to load and resolve artifact collection paths.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
const profilePathHolder = "{profile_path}"
const sidHolder = "{sid}"

var systemRelatedSIDs = []string{
	"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-80-", "S-1-5-82-", "S-1-5-96-",
}

// UserProfile represents a Windows user profile metadata.
type UserProfile struct {
	SID         string
	Username    string
	ProfilePath string
}

// BaseEntry represents a raw artifact definition from the configuration JSON.
type BaseEntry struct {
	Category string `json:"category"`
	Target   string `json:"target"`
}

// Entry represents a fully resolved collection target with its associated file paths.
type Entry struct {
	Category string
	Target   string
	Paths    []string
}

// Config aggregates all static, dynamic, and profile-specific collection targets.
type Config struct {
	StaticEntries  []BaseEntry
	DynamicEntries []BaseEntry
	ProfileEntries []BaseEntry
}

// UserConfig defines the schema for the external artifact configuration JSON.
type UserConfig struct {
	Override       bool        `json:"override"`
	StaticEntries  []BaseEntry `json:"static_entries"`
	DynamicEntries []BaseEntry `json:"dynamic_entries"`
	ProfileEntries []BaseEntry `json:"profile_entries"`
}

// New returns a Config populated with default artifact definitions.
func New() *Config {
	return &Config{
		// StaticEntries defines paths that are absolute and do not contain wildcards (e.g., $MFT).
		StaticEntries: []BaseEntry{
			{Category: "Filesystem", Target: `C:\$MFT`},
			{Category: "Filesystem", Target: `C:\$Extend\$UsnJrnl`},
			{Category: "Network", Target: `C:\Windows\System32\drivers\etc\hosts`},
		},
		// DynamicEntries defines system-wide paths that require wildcard expansion (e.g., Event Logs).
		DynamicEntries: []BaseEntry{
			{Category: "EventLog", Target: `C:\Windows\System32\winevt\Logs\*`},
			{Category: "Registry", Target: `C:\Windows\System32\config\SYSTEM*`},
			{Category: "Registry", Target: `C:\Windows\System32\config\SOFTWARE*`},
			{Category: "Registry", Target: `C:\Windows\System32\config\SAM*`},
			{Category: "Registry", Target: `C:\Windows\System32\config\SECURITY*`},
			{Category: "Execution", Target: `C:\Windows\Prefetch\*`},
			{Category: "Execution", Target: `C:\Windows\System32\Tasks\*`},
			{Category: "Execution", Target: `C:\Windows\Tasks\*`},
		},
		// ProfileEntries defines patterns expanded for each user profile via {profile_path} or {sid}.
		ProfileEntries: []BaseEntry{
			// Registry (Includes user-specific hives for manual analysis)
			{Category: "Registry", Target: `{profile_path}\NTUSER.DAT*`},
			{Category: "Registry", Target: `{profile_path}\AppData\Local\Microsoft\Windows\UsrClass.dat*`},

			// Execution (Command-line history)
			{Category: "Execution", Target: `{profile_path}\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`},

			// Web (Browser histories and caches)
			{Category: "Web", Target: `{profile_path}\AppData\Local\Google\Chrome\User Data\*\History`},
			{Category: "Web", Target: `{profile_path}\AppData\Local\Microsoft\Edge\User Data\*\History`},
			{Category: "Web", Target: `{profile_path}\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`},
			{Category: "Web", Target: `{profile_path}\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\History`},
			{Category: "Web", Target: `{profile_path}\AppData\Roaming\Opera Software\Opera Stable\*\History`},
			{Category: "Web", Target: `{profile_path}\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite`},

			// Activity (User file access tracks)
			{Category: "Activity", Target: `{profile_path}\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`},
			{Category: "Activity", Target: `{profile_path}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*`},
			{Category: "Activity", Target: `{profile_path}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*`},

			// RecycleBin (Deletion artifacts)
			{Category: "RecycleBin", Target: `C:\$Recycle.Bin\{sid}\$I*`},
		},
	}
}

// Load updates the collection configuration by merging embedded defaults with optional user overrides.
func Load(cfg *Config, path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var userCfg UserConfig
	if err := json.Unmarshal(file, &userCfg); err != nil {
		return err
	}

	if userCfg.Override {
		cfg.StaticEntries, cfg.DynamicEntries, cfg.ProfileEntries = userCfg.StaticEntries, userCfg.DynamicEntries, userCfg.ProfileEntries
	} else {
		cfg.StaticEntries = mergeConfig(cfg.StaticEntries, userCfg.StaticEntries)
		cfg.DynamicEntries = mergeConfig(cfg.DynamicEntries, userCfg.DynamicEntries)
		cfg.ProfileEntries = mergeConfig(cfg.ProfileEntries, userCfg.ProfileEntries)
	}
	return nil
}

// expandProfilePattern replaces {profile_path} or {sid} with profile-specific values.
func expandProfilePattern(target string, profile UserProfile) string {
	target = strings.ReplaceAll(target, profilePathHolder, profile.ProfilePath)
	target = strings.ReplaceAll(target, sidHolder, profile.SID)
	return target
}

// Prepare expands patterns and resolves environmental paths for collection.
func Prepare(cfg *Config) ([]Entry, []UserProfile, error) {
	var entries []Entry

	for _, entry := range cfg.StaticEntries {
		entries = append(entries, Entry{Category: entry.Category, Target: entry.Target, Paths: []string{entry.Target}})
	}

	for _, entry := range cfg.DynamicEntries {
		matches, err := filepath.Glob(entry.Target)
		if err != nil {
			return nil, nil, fmt.Errorf("glob %q: %w", entry.Target, err)
		}
		entries = append(entries, Entry{Category: entry.Category, Target: entry.Target, Paths: filterRegPaths(entry.Category, matches)})
	}

	profiles, err := profilesFromRegistry()
	if err != nil {
		return nil, nil, err
	}

	for _, profile := range profiles {
		for _, entry := range cfg.ProfileEntries {
			pattern := expandProfilePattern(entry.Target, profile)
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return nil, nil, fmt.Errorf("glob %q: %w", pattern, err)
			}
			entries = append(entries, Entry{Category: entry.Category, Target: pattern, Paths: filterRegPaths(entry.Category, matches)})
		}
	}
	return entries, profiles, nil
}

// filterRegPaths removes transaction log files (TM) from Registry category results.
func filterRegPaths(category string, srcPaths []string) []string {
	var paths []string
	for _, p := range srcPaths {
		if !(category == "Registry" && strings.Contains(p, "TM")) {
			paths = append(paths, p)
		}
	}
	return paths
}

// profilesFromRegistry enumerates active user profiles by querying the Windows ProfileList registry key.
func profilesFromRegistry() ([]UserProfile, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.READ)
	if err != nil {
		return nil, fmt.Errorf("open ProfileList: %w", err)
	}
	defer key.Close()

	sids, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("read SIDs: %w", err)
	}

	var profiles []UserProfile
	for _, sid := range sids {
		if isSystemSID(sid) {
			continue
		}

		subKey, err := registry.OpenKey(key, sid, registry.READ)
		if err != nil {
			continue
		}

		profilePath, _, err := subKey.GetStringValue("ProfileImagePath")
		username, _, _ := subKey.GetStringValue("Username")
		subKey.Close()

		if err != nil {
			continue
		}
		if _, err := os.Stat(profilePath); os.IsNotExist(err) {
			continue
		}

		profiles = append(profiles, UserProfile{SID: sid, Username: username, ProfilePath: profilePath})
	}
	return profiles, nil
}

// isSystemSID identifies built-in service accounts to exclude them from user-centric collection.
func isSystemSID(sid string) bool {
	for _, prefix := range systemRelatedSIDs {
		if strings.HasPrefix(sid, prefix) {
			return true
		}
	}
	return false
}

// mergeConfig appends unique entries from userEntries to masterEntries.
func mergeConfig(master, user []BaseEntry) []BaseEntry {
	for _, u := range user {
		exists := false
		for _, m := range master {
			if m.Target == u.Target {
				exists = true
				break
			}
		}
		if !exists {
			master = append(master, u)
		}
	}
	return master
}
