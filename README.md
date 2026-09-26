# 📦 collector

**High-Speed Windows Artifact Collection Tool for Cloud-Native DFIR**

`collector` is a lightweight, standalone tool written in **Go**, designed to collect critical Windows artifacts for incident response. It serves as the primary entry point for the **[veloxamen](https://www.google.com/search?q=https://github.com/veloxamen)** forensic pipeline.

## ✨ Key Concepts

* **Speed:** Designed for rapid triage with minimal impact on the target host.
* **Security:** Integrated with a cloud-native pipeline using **Cloud KMS** and RSA encryption for secure artifact handling. Minimizes legal and compliance risks by excluding PII (Personally Identifiable Information) where possible.
* **Simplicity:** A single-binary approach—no installation required.

---

## 🔑 Key Preparation (Security)

To execute the collector, a **4096-bit RSA PKIX public key** must be placed in the same directory as the executable.

* **Note:** The filename extension (excluding `.pub`) determines the file extension used for the collected encrypted data, so using an identifiable naming convention such as a case number (`for26001`) or a periodic identifier (`26q1`) is recommended.

### 🛠️ How to Generate Keys

#### A. Via the Veloxamen Pipeline (Recommended)

When using `deploy.sh`, the key ring and key set are generated automatically. Once you upload the resulting encrypted bundle to the ingestion bucket, it is automatically decrypted by the pipeline and ingested into BigQuery.

#### B. Manual Generation (GUI Tool - Windows)

You can use [RSAKeyGenerator](https://github.com/crabcanneryship/RSAKeyGenerator).

* Rename the generated keys to: `<name>.pri` (Private) and `<name>.pub` (Public).

#### C. Manual Generation (PowerShell)

```powershell
$rsa = [System.Security.Cryptography.RSA]::Create(4096)

# Generate Private Key
$privBytes = $rsa.ExportRSAPrivateKey()
$privB64 = [Convert]::ToBase64String($privBytes)
"-----BEGIN RSA PRIVATE KEY-----`n" + ($privB64 -replace '.{64}', "$&`n") + "`n-----END RSA PRIVATE KEY-----" | Out-File private.pem -Encoding ascii

# Generate Public Key
$pubBytes = $rsa.ExportSubjectPublicKeyInfo()
$pubB64 = [Convert]::ToBase64String($pubBytes)
"-----BEGIN PUBLIC KEY-----`n" + ($pubB64 -replace '.{64}', "$&`n") + "`n-----END PUBLIC KEY-----" | Out-File public.pem -Encoding ascii

```

#### D. Manual Generation (Bash / OpenSSL)

```bash
# Generate Private Key
openssl genrsa -out private.pem 4096

# Extract Public Key
openssl rsa -in private.pem -pubout -out public.pem

```

## 💻 Usage

### Basic Execution

> [!IMPORTANT]
> **Administrator privileges are required.** Please run `run.bat` included in this repository or execute the tool from an Administrator command prompt. No command-line arguments are required for standard triage.

### Command Line Options

| Option | Description | Default |
| --- | --- | --- |
| `-mem` | Acquire physical memory dump before artifact collection | `false` |
| `-config` | Path to artifact definition JSON | `built-in` |
| `-output` | Output directory | `current directory` |
| `-hash` | Compute SHA-256 hashes for all collected files | `false` |
| `-json-report` | Generate a detailed JSON report | `false` |
| `-verbose` | Enable verbose logging (debug mode) | `false` |
| `-max-file-size-mb` | Skip any single collected file above this size in MB | `1024` |
| `-usnjrnl` | Also collect `$UsnJrnl` (NTFS USN change journal) | `false` |

### Example

```bash
collector.exe -config "C:\Users\john\Desktop\append.json" -hash

```

## ⚙️ Configuration Samples

### 1. Appending to Defaults (`append.json`)

Use this to add specific targets while keeping the built-in collection rules.

```json
{
  "override": false,
  "static_entries": [
    { "category": "Network", "target": "C:\\Program Files\\TeamViewer\\Connections.txt" },
    { "category": "Activity", "target": "C:\\Windows\\System32\\sru\\SRUDB.dat" }
  ],
  "dynamic_entries": [
    { "category": "Activity", "target": "C:\\Windows\\Temp\\*" }
  ],
  "profile_entries": [
    { "category": "Web", "target": "{profile_path}\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Cache\\Cache_Data\\*" }
  ]
}

```

### 2. Overriding Defaults (`overwrite.config`)

Use this when you need total control, such as when the system drive is not C:.

```json
{
  "override": true,
  "static_entries": [
    { "category": "Filesystem", "target": "D:\\Windows\\$MFT" },
    { "category": "Network", "target": "D:\\Windows\\System32\\drivers\\etc\\hosts" }
  ],
  "dynamic_entries": [
    { "category": "EventLog", "target": "D:\\Windows\\System32\\winevt\\Logs\\*" },
    { "category": "Registry", "target": "D:\\Windows\\System32\\config\\SYSTEM*" }
  ],
  "profile_entries": [
    { "category": "RecycleBin", "target": "D:\\$Recycle.Bin\\{sid}\\$I*" }
  ]
}

```