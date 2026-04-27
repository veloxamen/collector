// Package config loads artifact collection definitions.
//
// # Built-in CSV format
//
//	# comment
//	type,locked,recursive,category,path
//	FILE,YES,NO,Registry,C:\Windows\System32\config\SYSTEM
//	DIR,YES,NO,EventLog,C:\Windows\System32\winevt\Logs
//	FILE,YES,NO,UserHive,C:\Users\{user}\NTUSER.DAT
//
// # Special types
//
//   - FILE, DIR: standard collection; path may contain {user} placeholder
//   - PROFILE_GLOB: browser / per-profile collection.
//     path is the base directory (may contain {user}).
//     The fifth field is a regexp matched against immediate child directory names.
//     The sixth field is a glob matched against files inside each matched profile dir.
//     Example:
//     PROFILE_GLOB,NO,NO,ChromeHistory,C:\Users\{user}\AppData\Local\Google\Chrome\User Data,^(Default|Profile \d+)$,History|Cookies|Preferences|Archived History
//
// # Future extension ideas for irregular paths
//
//	Add REGEX_PATH type where the path field itself is a regexp evaluated against
//	directory listings, allowing collection of paths that vary across systems or
//	software versions without modifying the binary.
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ── Default Excluded Users ────────────────────────────────────────────────────

var defaultExcludeUsers = []string{
	"Default",
	"Public",
	"defaultuser0",
	"defaultuser1",
	"All Users",
}

// ── Types ─────────────────────────────────────────────────────────────────────

// EntryType identifies the kind of collection entry.
type EntryType string

const (
	TypeFile        EntryType = "FILE"
	TypeDir         EntryType = "DIR"
	TypeProfileGlob EntryType = "PROFILE_GLOB" // browser multi-profile collection
)

// AcquisitionMethod represents how a file should be read.
type AcquisitionMethod int

const (
	MethodRaw AcquisitionMethod = iota // direct NTFS raw read (locked OS files)
	MethodOS                           // standard library os.Open
)

// Entry is one artifact definition row.
type Entry struct {
	Type      EntryType
	IsLocked  bool // true → use raw NTFS acquisition
	Recursive bool // DIR only
	Category  string
	Path      string // base path; may contain {user}

	// PROFILE_GLOB fields:
	ProfileRegex string // regexp for profile dir names (e.g. "^(Default|Profile \d+)$")
	FileGlob     string // pipe-separated file names inside profile (e.g. "History|Cookies")
}

type Entry2 struct {
	Category string
	Command  string
	Paths    []string
}

// AcquisitionMethod returns the method for this entry.
func (e *Entry) AcquisitionMethod() AcquisitionMethod {
	if e.IsLocked {
		return MethodRaw
	}
	return MethodOS
}

// HasUserPlaceholder reports whether Path contains {user}.
func HasUserPlaceholder(path string) bool {
	return strings.Contains(path, "{user}")
}

// Config holds the full loaded configuration.
type Config struct {
	ExcludeUsers []string
	Entries      []Entry
}

// Config holds the pre loaded configuration.
type Config2 struct {
	FixedPaths    []Entry2 `json:"fixed_paths"`
	WildcardPaths []Entry2 `json:"wildcard_paths"`
	UserPaths     []Entry2 `json:"user_paths"`
}

// Config holds the user defined configuration.
type UserConfig struct {
	Override      bool     `json:"override"`
	FixedPaths    []Entry2 `json:"fixed_paths"`
	WildcardPaths []Entry2 `json:"wildcard_paths"`
	UserPaths     []Entry2 `json:"user_paths"`
}

// ExpandUserPath replaces {user} in path with username.
func (cfg *Config) ExpandUserPath(path, user string) string {
	return strings.ReplaceAll(path, "{user}", user)
}

// IsExcludedUser reports whether username is in the exclusion list (case-insensitive).
func (cfg *Config) IsExcludedUser(username string) bool {
	lower := strings.ToLower(username)
	for _, ex := range cfg.ExcludeUsers {
		if strings.ToLower(ex) == lower {
			return true
		}
	}
	return false
}

// ── Built-in Defaults ─────────────────────────────────────────────────────────

// New returns the default built-in artifact configuration.
func NewNew() *Config2 {
	return &Config2{
		FixedPaths: []Entry2{
			{Category: "Filesystem", Command: `C:\$MFT`},
			{Category: "Filesystem", Command: `C:\$Extend\$UsnJrnl`},
		},
		WildcardPaths: []Entry2{
			{Category: "EventLog", Command: `C:\Windows\System32\winevt\Logs\*`},
			{Category: "Registry", Command: `C:\Windows\System32\config\SYSTEM*`},
			{Category: "Registry", Command: `C:\Windows\System32\config\SOFTWARE*`},
			{Category: "Registry", Command: `C:\Windows\System32\config\SAM*`},
			{Category: "Registry", Command: `C:\Windows\System32\config\SECURITY*`},
			{Category: "Prefetch", Command: `C:\Windows\Prefetch\*`},
			{Category: "RecycleBin", Command: `C:\$Recycle.Bin\$I*`},
		},
		UserPaths: []Entry2{
			{Category: "Registry", Command: `{imagePath}\NTUSER.DAT*`},
			{Category: "Registry", Command: `{imagePath}\UsrClass.dat*`},
			{Category: "Web", Command: `{imagePath}\AppData\Local\Google\Chrome\User Data\*\History`},
			{Category: "Web", Command: `{imagePath}\AppData\Local\Microsoft\Edge\User Data\*\History`},
			{Category: "Web", Command: `{imagePath}\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`},
			{Category: "Web", Command: `{imagePath}\AppData\Local\BraveSoftware\Brave-Browser\User Data\*\History`},
			{Category: "Web", Command: `{imagePath}\AppData\Roaming\Opera Software\Opera Stable\*\History`},
			{Category: "Web", Command: `{imagePath}\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite`},
			{Category: "Recent", Command: `{imagePath}\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`},
			{Category: "Recent", Command: `{imagePath}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*`},
		},
	}
}

// New returns the default built-in artifact configuration.
func New() *Config {
	return &Config{
		ExcludeUsers: []string{"Default", "Public", "All Users", "defaultuser0", "defaultuser1"},
		Entries: []Entry{
			// ── MFT & journal ─────────────────────────────────────────────
			{Type: TypeFile, IsLocked: true, Category: "MFT", Path: `C:\$MFT`},
			{Type: TypeFile, IsLocked: true, Category: "USNJournal", Path: `C:\$Extend\$UsnJrnl`},

			// ── Event logs ────────────────────────────────────────────────
			{Type: TypeDir, IsLocked: true, Recursive: false, Category: "EventLog",
				Path: `C:\Windows\System32\winevt\Logs`},

			// ── System registry hives ─────────────────────────────────────
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SYSTEM`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SYSTEM.LOG1`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SYSTEM.LOG2`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SOFTWARE`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SOFTWARE.LOG1`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SOFTWARE.LOG2`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SAM`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SAM.LOG1`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SAM.LOG2`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SECURITY`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SECURITY.LOG1`},
			{Type: TypeFile, IsLocked: true, Category: "Registry", Path: `C:\Windows\System32\config\SECURITY.LOG2`},

			// ── User registry hives ───────────────────────────────────────
			{Type: TypeFile, IsLocked: true, Category: "UserHive", Path: `C:\Users\{user}\NTUSER.DAT`},
			{Type: TypeFile, IsLocked: true, Category: "UserHive", Path: `C:\Users\{user}\NTUSER.DAT.LOG1`},
			{Type: TypeFile, IsLocked: true, Category: "UserHive", Path: `C:\Users\{user}\NTUSER.DAT.LOG2`},
			{Type: TypeFile, IsLocked: true, Category: "UserHive",
				Path: `C:\Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat`},
			{Type: TypeFile, IsLocked: true, Category: "UserHive",
				Path: `C:\Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG1`},
			{Type: TypeFile, IsLocked: true, Category: "UserHive",
				Path: `C:\Users\{user}\AppData\Local\Microsoft\Windows\UsrClass.dat.LOG2`},

			// ── Browser: Chrome (all profiles via PROFILE_GLOB) ───────────
			{
				Type: TypeProfileGlob, IsLocked: false, Category: "Chrome",
				Path:         `C:\Users\{user}\AppData\Local\Google\Chrome\User Data`,
				ProfileRegex: `^(Default|Profile \d+)$`,
				FileGlob:     "History|Archived History|Cookies|Preferences|Login Data|Bookmarks|Web Data",
			},

			// ── Browser: Edge (all profiles) ──────────────────────────────
			{
				Type: TypeProfileGlob, IsLocked: false, Category: "Edge",
				Path:         `C:\Users\{user}\AppData\Local\Microsoft\Edge\User Data`,
				ProfileRegex: `^(Default|Profile \d+)$`,
				FileGlob:     "History|Archived History|Cookies|Preferences|Login Data|Bookmarks|Web Data",
			},

			// ── Browser: Firefox (all profiles) ───────────────────────────
			// Firefox stores profiles under Profiles/<random>.default[-release]
			{
				Type: TypeProfileGlob, IsLocked: false, Category: "Firefox",
				Path:         `C:\Users\{user}\AppData\Roaming\Mozilla\Firefox\Profiles`,
				ProfileRegex: `^.+\.(default|default-release|default-esr)$`,
				FileGlob:     "places.sqlite|cookies.sqlite|formhistory.sqlite|logins.json|key4.db",
			},

			// ── Browser: Opera ────────────────────────────────────────────
			{
				Type: TypeProfileGlob, IsLocked: false, Category: "Opera",
				Path:         `C:\Users\{user}\AppData\Roaming\Opera Software\Opera Stable`,
				ProfileRegex: `^(Default|Profile \d+)$`,
				FileGlob:     "History|Cookies|Preferences",
			},

			// ── Browser: Safari ───────────────────────────────────────────
			{Type: TypeFile, IsLocked: false, Category: "Safari",
				Path: `C:\Users\{user}\AppData\Roaming\Apple Computer\Safari\History.db`},
			{Type: TypeFile, IsLocked: false, Category: "Safari",
				Path: `C:\Users\{user}\AppData\Roaming\Apple Computer\Safari\Cookies\Cookies.binarycookies`},

			// ── IE / Legacy WebCache ───────────────────────────────────────
			{Type: TypeFile, IsLocked: false, Category: "IEHistory",
				Path: `C:\Users\{user}\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`},

			// ── Prefetch ──────────────────────────────────────────────────
			{Type: TypeDir, IsLocked: false, Recursive: false, Category: "Prefetch",
				Path: `C:\Windows\Prefetch`},

			// ── Recycle Bin ───────────────────────────────────────────────
			{Type: TypeDir, IsLocked: false, Recursive: true, Category: "RecycleBin",
				Path: `C:\$Recycle.Bin`},
		},
	}
}

func LoadAndMerge(cfg *Config2, path string) error {

	file, err := os.ReadFile(path)

	if err != nil {
		// If file doesn't exist, we just keep defaults
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
		cfg.FixedPaths = userCfg.FixedPaths
		cfg.WildcardPaths = userCfg.WildcardPaths
		cfg.UserPaths = userCfg.UserPaths
	} else {
		// Logic: Append user artifacts to defaults
		cfg.FixedPaths = append(cfg.FixedPaths, userCfg.FixedPaths...)
		cfg.WildcardPaths = append(cfg.WildcardPaths, userCfg.WildcardPaths...)
		cfg.UserPaths = append(cfg.UserPaths, userCfg.UserPaths...)
	}

	return nil
}

func Extend(cfg *Config2) error {
	// FixedPaths
	for _, entry := range cfg.FixedPaths {
		entry.Paths = []string{entry.Command}
	}
	// WildcardPaths
	for _, entry := range cfg.WildcardPaths {
		matches, err := filepath.Glob(entry.Command)
		if err != nil {
			return fmt.Errorf("error : %w", err)
		}
		for _, match := range matches {
			entry.Paths = append(entry.Paths, match)
		}
	}
	// UserPaths

	for _, entry := range cfg.UserPaths {
		matches, err := filepath.Glob(entry.Command)
		if err != nil {
			return fmt.Errorf("error : %w", err)
		}
		for _, match := range matches {
			entry.Paths = append(entry.Paths, match)
		}
	}

	return nil
}

// ── CSV Loader ────────────────────────────────────────────────────────────────

// Load reads a CSV config file and returns a Config.
//
// Column layout for FILE / DIR:
//
//	type, locked(YES/NO), recursive(YES/NO), category, path
//
// Column layout for PROFILE_GLOB:
//
//	PROFILE_GLOB, locked, NO, category, basePath, profileRegex, fileGlob
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open config (%s): %w", path, err)
	}
	defer f.Close()

	cfg := &Config{ExcludeUsers: append([]string{}, defaultExcludeUsers...)}
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// exclude_users override
		if strings.HasPrefix(strings.ToLower(line), "exclude_users,") {
			parts := strings.Split(line, ",")
			cfg.ExcludeUsers = make([]string, 0, len(parts)-1)
			for _, u := range parts[1:] {
				if t := strings.TrimSpace(u); t != "" {
					cfg.ExcludeUsers = append(cfg.ExcludeUsers, t)
				}
			}
			continue
		}

		fields := splitCSV(line)
		if len(fields) < 5 {
			return nil, fmt.Errorf("line %d: need at least 5 columns", lineNum)
		}

		entType := EntryType(strings.ToUpper(strings.TrimSpace(fields[0])))
		locked := strings.ToUpper(strings.TrimSpace(fields[1])) == "YES"
		recursive := strings.ToUpper(strings.TrimSpace(fields[2])) == "YES"
		category := strings.TrimSpace(fields[3])
		entPath := strings.TrimSpace(fields[4])

		switch entType {
		case TypeFile, TypeDir:
			cfg.Entries = append(cfg.Entries, Entry{
				Type: entType, IsLocked: locked, Recursive: recursive,
				Category: category, Path: entPath,
			})
		case TypeProfileGlob:
			if len(fields) < 7 {
				return nil, fmt.Errorf("line %d: PROFILE_GLOB needs 7 columns", lineNum)
			}
			cfg.Entries = append(cfg.Entries, Entry{
				Type: TypeProfileGlob, IsLocked: locked, Category: category,
				Path:         entPath,
				ProfileRegex: strings.TrimSpace(fields[5]),
				FileGlob:     strings.TrimSpace(fields[6]),
			})
		default:
			return nil, fmt.Errorf("line %d: unknown type %q", lineNum, fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("CSV scan error: %w", err)
	}
	if len(cfg.Entries) == 0 {
		return nil, fmt.Errorf("no entries found in %s", path)
	}
	return cfg, nil
}

func splitCSV(line string) []string {
	return strings.Split(line, ",")
}
