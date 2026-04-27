//go:build windows

// Package ntfs opens \\.\X: in raw mode and directly parses NTFS structures to return file contents.
//
// Processing flow:
//  1. Open volume with CreateFile (FILE_FLAG_NO_BUFFERING)
//  2. Retrieve parameters via FSCTL_GET_NTFS_VOLUME_DATA
//  3. Load the entire MFT from inode 0 data runs
//  4. Scan MFT linearly and resolve target inode via $FILE_NAME attributes
//  5. Return file contents from the inode $DATA attribute (resident/non-resident)
package ntfs

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ── Win32 Constants ──────────────────────────────────────────────────────────────

const (
	fileFlagNoBuffering = 0x20000000
	fileFlagBackupSem   = 0x02000000
	genericRead         = 0x80000000
	fileShareReadWrite  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	fsctlGetNtfsVolData = 0x00090064 // FSCTL_GET_NTFS_VOLUME_DATA
)

// ── NTFS_VOLUME_DATA_BUFFER (excerpt) ──────────────────────────────────────────

type ntfsVolumeData struct {
	VolumeSerialNumber           int64
	NumberSectors                int64
	TotalClusters                int64
	FreeClusters                 int64
	TotalReserved                int64
	BytesPerSector               uint32
	BytesPerCluster              uint32
	BytesPerFileRecordSegment    uint32
	ClustersPerFileRecordSegment uint32
	MftValidDataLength           int64
	MftStartLcn                  int64
	Mft2StartLcn                 int64
	MftZoneStart                 int64
	MftZoneEnd                   int64
}

// ── VolumeHandle ────────────────────────────────────────────────────────────────

// VolumeHandle holds an open volume handle and NTFS metadata.
type VolumeHandle struct {
	handle             windows.Handle
	bytesPerSector     uint64
	bytesPerCluster    uint64
	mftStartLCN        uint64
	bytesPerFileRecord uint64
}

// Open opens \\.\<volume> with FILE_FLAG_NO_BUFFERING and returns a VolumeHandle.
func Open(volume string) (*VolumeHandle, error) {
	vol := strings.TrimRight(volume, `\`)
	// volume accepts either "C" (no colon) or "C:"
	if !strings.HasSuffix(vol, ":") {
		vol = vol + ":"
	}
	path := `\\.\` + vol

	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		pathPtr,
		genericRead,
		fileShareReadWrite,
		nil,
		windows.OPEN_EXISTING,
		fileFlagNoBuffering,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open volume %s: %w", path, err)
	}

	var data ntfsVolumeData
	var returned uint32
	err = windows.DeviceIoControl(
		handle,
		fsctlGetNtfsVolData,
		nil, 0,
		(*byte)(unsafe.Pointer(&data)),
		uint32(unsafe.Sizeof(data)),
		&returned,
		nil,
	)
	if err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("FSCTL_GET_NTFS_VOLUME_DATA failed: %w", err)
	}

	log.Printf("[INFO] NTFS volume opened: BytesPerSector=%d BytesPerCluster=%d BytesPerFileRecord=%d MftStartLCN=%d",
		data.BytesPerSector, data.BytesPerCluster,
		data.BytesPerFileRecordSegment, data.MftStartLcn)
	if data.BytesPerSector != 512 {
		log.Printf("[WARN] Non-standard sector size: %d bytes (Advanced Format / VMware / cloud disk?) — alignment-sensitive read path is active",
			data.BytesPerSector)
	}

	return &VolumeHandle{
		handle:             handle,
		bytesPerSector:     uint64(data.BytesPerSector),
		bytesPerCluster:    uint64(data.BytesPerCluster),
		mftStartLCN:        uint64(data.MftStartLcn),
		bytesPerFileRecord: uint64(data.BytesPerFileRecordSegment),
	}, nil
}

// Close closes the volume handle.
func (v *VolumeHandle) Close() {
	windows.CloseHandle(v.handle)
}

// ── Raw Read ────────────────────────────────────────────────────────────────────

// readRaw reads length bytes starting at offset.
// Aligns to sector boundary as required by FILE_FLAG_NO_BUFFERING, then trims to the requested range.
func (v *VolumeHandle) readRaw(offset, length uint64) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	sector := v.bytesPerSector
	alignedOffset := (offset / sector) * sector
	prefix := offset - alignedOffset
	rawLen := ((prefix + length + sector - 1) / sector) * sector

	_, err := windows.Seek(v.handle, int64(alignedOffset), 0 /* io.SeekStart */)
	if err != nil {
		return nil, fmt.Errorf("seek failed offset=%d: %w", alignedOffset, err)
	}

	buf := make([]byte, rawLen)
	var bytesRead uint32
	err = windows.ReadFile(v.handle, buf, &bytesRead, nil)
	if err != nil && err != syscall.ERROR_HANDLE_EOF {
		return nil, fmt.Errorf("ReadFile failed offset=%d len=%d: %w", alignedOffset, rawLen, err)
	}

	available := uint64(bytesRead)
	if prefix > available {
		return nil, fmt.Errorf("readRaw: prefix(%d) exceeds bytesRead(%d) at alignedOffset=%d (sector=%d)",
			prefix, available, alignedOffset, sector)
	}
	end := prefix + length
	if end > available {
		end = available // EOF 付近のクリップ
	}
	// スライス参照ではなくコピーを返す。
	// buf は rawLen (最大 sector の倍数) 単位で確保されており、
	// スライスを返すと大きなバッキング配列が GC されずに残り、
	// 呼び出し側で append 連結したときに境界バグの原因になる。
	result := make([]byte, end-prefix)
	copy(result, buf[prefix:end])
	return result, nil
}

// ── MFT Record Reading ──────────────────────────────────────────────────────────

func (v *VolumeHandle) readFileRecord(inode uint64) ([]byte, error) {
	mftOffset := v.mftStartLCN * v.bytesPerCluster
	recordOffset := mftOffset + inode*v.bytesPerFileRecord
	return v.readRaw(recordOffset, v.bytesPerFileRecord)
}

// readMFTData loads the entire MFT from inode 0 ($MFT) data runs.
func (v *VolumeHandle) readMFTData() ([]byte, error) {
	record, err := v.readFileRecord(0)
	if err != nil {
		return nil, fmt.Errorf("failed to read MFT inode 0: %w", err)
	}

	runs, err := parseDataRuns(record, v.bytesPerFileRecord)
	if err != nil {
		return nil, err
	}
	if len(runs) == 0 {
		return getResidentData(record)
	}

	realSize := getNonResidentDataSize(record)
	var out []byte
	for _, run := range runs {
		offset := run.LCN * v.bytesPerCluster
		length := run.Clusters * v.bytesPerCluster
		chunk, err := v.readRaw(offset, length)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if realSize > 0 && uint64(len(out)) >= realSize {
			break
		}
	}
	if realSize > 0 && uint64(len(out)) > realSize {
		out = out[:realSize]
	}
	// Apply USA fixup to each MFT record
	applyUSAFixupToMFT(out, v.bytesPerFileRecord)
	return out, nil
}

// applyUSAFixupToMFT applies USA fixup to every record in the MFT buffer.
func applyUSAFixupToMFT(mftData []byte, recordSize uint64) {
	total := uint64(len(mftData)) / recordSize
	for i := uint64(0); i < total; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]
		if len(record) >= 4 && string(record[0:4]) == "FILE" {
			applyUSAFixup(record) // in-place: modifies mftData slice directly
		}
	}
}

// ── File Lookup & Content Retrieval ────────────────────────────────────────────

// ReadFileByPath returns file contents for a volume-relative path (e.g. "$MFT", "Windows\\System32\\config\\SYSTEM").

func (v *VolumeHandle) ReadFileByPath(relPath string) ([]byte, error) {
	if strings.EqualFold(relPath, "$MFT") {
		log.Println("[DEBUG] $MFT: reading directly from inode 0")
		return v.readMFTData()
	}

	log.Println("[DEBUG] Loading full MFT...")
	mftData, err := v.readMFTData()
	if err != nil {
		return nil, fmt.Errorf("MFT load failed: %w", err)
	}
	log.Printf("[DEBUG] MFT loaded: %d bytes (%d records)",
		len(mftData), uint64(len(mftData))/v.bytesPerFileRecord)

	targetInode, err := findInodeByPath(mftData, relPath, v.bytesPerFileRecord)
	if err != nil {
		return nil, err
	}
	log.Printf("[DEBUG] inode resolved: %s → %d", relPath, targetInode)

	recStart := targetInode * v.bytesPerFileRecord
	recEnd := recStart + v.bytesPerFileRecord
	if recEnd > uint64(len(mftData)) {
		return nil, fmt.Errorf("record for inode %d is out of MFT range", targetInode)
	}
	record := mftData[recStart:recEnd]

	return v.readFileData(record)
}

func (v *VolumeHandle) readFileData(record []byte) ([]byte, error) {
	runs, err := parseDataRuns(record, v.bytesPerFileRecord)
	if err == nil && len(runs) > 0 {
		realSize := getNonResidentDataSize(record)
		var out []byte
		for _, run := range runs {
			offset := run.LCN * v.bytesPerCluster
			length := run.Clusters * v.bytesPerCluster
			chunk, err := v.readRaw(offset, length)
			if err != nil {
				return nil, err
			}
			out = append(out, chunk...)
			if realSize > 0 && uint64(len(out)) >= realSize {
				break
			}
		}
		if realSize > 0 && uint64(len(out)) > realSize {
			out = out[:realSize]
		}
		return out, nil
	}
	return getResidentData(record)
}

// ── NTFS File Record Parser ─────────────────────────────────────────────────────

type dataRun struct {
	LCN      uint64
	Clusters uint64
}

// applyUSAFixup applies Update Sequence Array (USA) fixup to an MFT record.
// NTFS overwrites the last 2 bytes of each 512-byte sector with a USA entry on write.
// Restoring the original values is necessary to avoid corrupt attribute data.
// record is modified in place.
func applyUSAFixup(record []byte) bool {
	if len(record) < 8 {
		return false
	}
	// +0x04: USA offset (2B)
	// +0x06: USA entry count (sequence number + sector count)
	usaOffset := int(binary.LittleEndian.Uint16(record[4:6]))
	usaCount := int(binary.LittleEndian.Uint16(record[6:8]))
	if usaOffset < 8 || usaCount < 2 || usaOffset+usaCount*2 > len(record) {
		return false
	}
	// USA[0] = sequence number (expected at the end of each sector)
	seqNum := binary.LittleEndian.Uint16(record[usaOffset:])
	// USA[1..] = original values per sector (sector count = usaCount-1)
	for i := 1; i < usaCount; i++ {
		sectorEnd := i*512 - 2
		if sectorEnd+2 > len(record) {
			break
		}
		// Verify sequence number at sector end
		if binary.LittleEndian.Uint16(record[sectorEnd:]) != seqNum {
			// Mismatch: record may be corrupt or USA is not applicable
			continue
		}
		// Restore original value
		orig := binary.LittleEndian.Uint16(record[usaOffset+i*2:])
		binary.LittleEndian.PutUint16(record[sectorEnd:], orig)
	}
	return true
}

func isValidFileRecord(record []byte) bool {
	return len(record) >= 4 && string(record[0:4]) == "FILE"
}

// parseDataRuns returns data runs from the $DATA attribute (type=0x80).

// collectDataRuns gathers all $DATA data runs from records, considering $ATTRIBUTE_LIST.

func (s *Session) collectDataRuns(record []byte) ([]dataRun, uint64, error) {
	// First, look for $DATA in the same record
	runs, err := parseDataRuns(record, s.recordSize)
	if err != nil {
		return nil, 0, err
	}
	realSize := getNonResidentDataSize(record)
	if len(runs) > 0 {
		return runs, realSize, nil
	}

	// No $DATA found — look for $ATTRIBUTE_LIST
	// 1. Resident $ATTRIBUTE_LIST
	if attrListData := getAttributeListData(record); attrListData != nil {
		return s.scanAttrList(attrListData)
	}

	// 2. Non-resident $ATTRIBUTE_LIST — read via vol.readRaw
	attrListRuns := findAttributeListRuns(record)
	if len(attrListRuns) == 0 {
		return nil, 0, nil // resident data or no file
	}
	attrListData, err := s.readRunsRaw(attrListRuns)
	if err != nil || len(attrListData) == 0 {
		return nil, 0, nil
	}
	return s.scanAttrList(attrListData)
}

// scanAttrList scans $ATTRIBUTE_LIST data and collects $DATA (0x80) data runs.
func (s *Session) scanAttrList(data []byte) ([]dataRun, uint64, error) {
	var allRuns []dataRun
	var foundSize uint64
	for pos := 0; pos+26 <= len(data); {
		attrType := binary.LittleEndian.Uint32(data[pos : pos+4])
		entryLen := int(binary.LittleEndian.Uint16(data[pos+4 : pos+6]))
		if entryLen == 0 {
			break
		}
		if attrType == 0x80 { // $DATA
			ref := binary.LittleEndian.Uint64(data[pos+0x10 : pos+0x18])
			extInode := ref & 0x0000FFFFFFFFFFFF
			extRecord := getRecordByInode(s.mftData, extInode, s.recordSize)
			if extRecord != nil {
				extRuns, _ := parseDataRuns(extRecord, s.recordSize)
				if len(extRuns) > 0 {
					allRuns = append(allRuns, extRuns...)
					if foundSize == 0 {
						foundSize = getNonResidentDataSize(extRecord)
					}
				}
			}
		}
		pos += entryLen
	}
	return allRuns, foundSize, nil
}

// readRunsRaw reads and concatenates data runs directly from the volume.
func (s *Session) readRunsRaw(runs []dataRun) ([]byte, error) {
	var out []byte
	for _, run := range runs {
		offset := run.LCN * s.handle.bytesPerCluster
		length := run.Clusters * s.handle.bytesPerCluster
		chunk, err := s.handle.readRaw(offset, length)
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// findAttributeListRuns returns $ATTRIBUTE_LIST (0x20) data runs from an MFT record.

func findAttributeListRuns(record []byte) []dataRun {
	if len(record) < 0x18 {
		return nil
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x20 { // $ATTRIBUTE_LIST
			nonRes := record[pos+8]
			if nonRes == 0 {
				// resident: return data directly (no data runs)
				return []dataRun{{LCN: 0, Clusters: 0}} // sentinel: resident, handled separately
			}
			if pos+0x22 <= len(record) {
				runOff := int(binary.LittleEndian.Uint16(record[pos+0x20 : pos+0x22]))
				if runOff > 0 && pos+runOff <= len(record) {
					runs, _ := decodeDataRuns(record[pos+runOff : pos+attrLen])
					return runs
				}
			}
		}
		pos += attrLen
	}
	return nil
}

// getAttributeListData returns the data of a resident $ATTRIBUTE_LIST.
func getAttributeListData(record []byte) []byte {
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x20 && record[pos+8] == 0 && pos+0x16 <= len(record) {
			contOff := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			contLen := int(binary.LittleEndian.Uint32(record[pos+0x10 : pos+0x14]))
			s := pos + contOff
			if s+contLen <= len(record) {
				return record[s : s+contLen]
			}
		}
		pos += attrLen
	}
	return nil
}

// getRecordByInode returns an MFT record from the cache by actual inode number.
func getRecordByInode(mftData []byte, inode uint64, recordSize uint64) []byte {
	// fast path
	start := inode * recordSize
	end := start + recordSize
	if end <= uint64(len(mftData)) {
		record := mftData[start:end]
		if isValidFileRecord(record) && len(record) >= 0x30 {
			if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
				return record
			}
		}
	}
	// linear scan
	total := uint64(len(mftData)) / recordSize
	for i := uint64(0); i < total; i++ {
		s := i * recordSize
		e := s + recordSize
		if e > uint64(len(mftData)) {
			break
		}
		record := mftData[s:e]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
			return record
		}
	}
	return nil
}

func parseDataRuns(record []byte, _ uint64) ([]dataRun, error) {
	if !isValidFileRecord(record) {
		return nil, fmt.Errorf("invalid FILE record signature")
	}
	if len(record) < 0x18 {
		return nil, fmt.Errorf("FILE record too short")
	}

	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x80 { // $DATA
			nonResident := record[pos+8]
			if nonResident == 0 {
				return nil, nil // resident
			}
			// non-resident attribute: data runs offset is a uint16 at +0x20
			if pos+0x22 > len(record) {
				break
			}
			runOffset := int(binary.LittleEndian.Uint16(record[pos+0x20 : pos+0x22]))
			if runOffset == 0 || pos+runOffset > len(record) {
				break
			}
			runs, err := decodeDataRuns(record[pos+runOffset : pos+attrLen])
			return runs, err
		}
		pos += attrLen
	}
	return nil, nil
}

// decodeDataRuns decodes a data-run byte stream into (absolute LCN, cluster count) pairs.
func decodeDataRuns(data []byte) ([]dataRun, error) {
	var runs []dataRun
	pos := 0
	var currentLCN int64

	for pos < len(data) {
		header := data[pos]
		if header == 0 {
			break
		}
		pos++

		lenBytes := int(header & 0x0F)
		offsetBytes := int(header >> 4)

		if pos+lenBytes+offsetBytes > len(data) {
			break
		}

		// cluster count (unsigned)
		var clusterCount uint64
		for i := 0; i < lenBytes; i++ {
			clusterCount |= uint64(data[pos+i]) << (i * 8)
		}
		pos += lenBytes

		// LCN delta (signed)
		var lcnDelta int64
		for i := 0; i < offsetBytes; i++ {
			lcnDelta |= int64(data[pos+i]) << (i * 8)
		}
		// sign-extend
		if offsetBytes > 0 && data[pos+offsetBytes-1]&0x80 != 0 {
			lcnDelta |= ^((int64(1) << (offsetBytes * 8)) - 1)
		}
		pos += offsetBytes

		currentLCN += lcnDelta
		runs = append(runs, dataRun{LCN: uint64(currentLCN), Clusters: clusterCount})
	}
	return runs, nil
}

// getResidentData returns the content of a resident $DATA attribute.
func getResidentData(record []byte) ([]byte, error) {
	if !isValidFileRecord(record) {
		return nil, fmt.Errorf("invalid FILE record")
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x80 && record[pos+8] == 0 {
			if pos+0x16 <= len(record) {
				contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
				contentLength := int(binary.LittleEndian.Uint32(record[pos+0x10 : pos+0x14]))
				start := pos + contentOffset
				end := start + contentLength
				if end <= len(record) {
					result := make([]byte, contentLength)
					copy(result, record[start:end])
					return result, nil
				}
			}
		}
		pos += attrLen
	}
	// $DATA attribute not found as a resident attribute.
	// Active transaction log files (e.g. SYSTEM.LOG1/LOG2) can have a
	// $DATA attribute that is empty or sparse while locked by the kernel.
	// Return an empty slice so the caller stores a zero-byte entry instead
	// of treating this as a collection failure.
	return []byte{}, nil
}

// getNonResidentDataSize returns the real data size of a non-resident $DATA attribute. 0 = unknown.
func getNonResidentDataSize(record []byte) uint64 {
	if len(record) < 0x18 {
		return 0
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x80 && record[pos+8] == 1 && pos+0x38 <= len(record) {
			// real size @ +0x30 (8B)
			return binary.LittleEndian.Uint64(record[pos+0x30 : pos+0x38])
		}
		pos += attrLen
	}
	return 0
}

// ── MFT Scan: Path → Inode Resolution ───────────────────────────────────────────

func findInodeByPath(mftData []byte, relPath string, recordSize uint64) (uint64, error) {
	components := splitPath(relPath)
	// NTFS root directory is inode 5
	parentInode := uint64(5)

	for _, component := range components {
		inode, err := findChildInode(mftData, parentInode, component, recordSize)
		if err != nil {
			return 0, fmt.Errorf("'%s' not found (parent inode=%d): %w",
				component, parentInode, err)
		}
		parentInode = inode
	}
	return parentInode, nil
}

func findChildInode(mftData []byte, parentInode uint64, name string, recordSize uint64) (uint64, error) {
	totalRecords := uint64(len(mftData)) / recordSize

	for i := uint64(0); i < totalRecords; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]

		if !isValidFileRecord(record) {
			continue
		}
		if len(record) < 0x30 {
			continue
		}
		// flags bit0 = in-use
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue
		}

		if checkFileNameAttr(record, parentInode, name) {
			// Return the actual inode number stored at MFT record offset +0x2C.
			// Using the record-internal value (not the array index i) ensures correct
			// parent inode tracking even in fragmented MFT environments.
			actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))
			return actualInode, nil
		}
	}
	return 0, fmt.Errorf("'%s' (parent=%d) not found in MFT", name, parentInode)
}

// checkFileNameAttr checks $FILE_NAME attributes (0x30) against parent inode and filename.
// NTFS may store multiple $FILE_NAME attributes per file (Win32, DOS 8.3, POSIX).
// Returns true if any one of them matches.
func checkFileNameAttr(record []byte, parentInode uint64, name string) bool {
	if len(record) < 0x18 {
		return false
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x30 { // $FILE_NAME
			// Check all $FILE_NAME attributes; return true immediately on any match
			if matchFileNameAttr(record, pos, parentInode, name) {
				return true
			}
		}
		pos += attrLen
	}
	return false
}

// matchFileNameAttr checks a single $FILE_NAME attribute starting at pos.
// $FILE_NAME attribute layout:
//
//	Attribute header (pos): type(4) len(4) nonResident(1) nameLen(1) nameOffset(2) flags(2) id(2)
//	Resident header (pos+0x10): contentLen(4) contentOffset(2) ...
//	Content:
//	  +0x00: Parent MFT reference (8B: low 48 bits = inode number)
//	  +0x40: Filename length (1B, UTF-16 character count)
//	  +0x41: Namespace (1B: 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS)
//	  +0x42: Filename (UTF-16LE)
func matchFileNameAttr(record []byte, pos int, parentInode uint64, name string) bool {
	if pos+0x16 > len(record) {
		return false
	}
	contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
	cs := pos + contentOffset

	if cs+0x42 > len(record) {
		return false
	}

	parRef := binary.LittleEndian.Uint64(record[cs : cs+8])
	par := parRef & 0x0000FFFFFFFFFFFF

	nameLen := int(record[cs+0x40])
	nameStart := cs + 0x42
	nameEnd := nameStart + nameLen*2
	if nameEnd > len(record) {
		return false
	}

	utf16 := make([]uint16, nameLen)
	for i := range utf16 {
		utf16[i] = binary.LittleEndian.Uint16(record[nameStart+i*2:])
	}
	fname := windows.UTF16ToString(utf16)

	return par == parentInode && strings.EqualFold(fname, name)
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range strings.FieldsFunc(p, func(r rune) bool {
		return r == '\\' || r == '/'
	}) {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

// ── Public API for the collector package ─────────────────────────────────────────

// MatchEntry represents a file or directory matched during MFT scanning.
type MatchEntry struct {
	Name  string
	Inode uint64
}

// BytesPerFileRecord returns the size of one MFT record in bytes.
func (v *VolumeHandle) BytesPerFileRecord() uint64 {
	return v.bytesPerFileRecord
}

// ReadMFT returns the entire MFT as a byte slice.
func (v *VolumeHandle) ReadMFT() ([]byte, error) {
	return v.readMFTData()
}

// ReadFileByInode returns file content for the given inode.
// mftData must be obtained via ReadMFT().
func (v *VolumeHandle) ReadFileByInode(mftData []byte, inode uint64) ([]byte, error) {
	recStart := inode * v.bytesPerFileRecord
	recEnd := recStart + v.bytesPerFileRecord
	if recEnd > uint64(len(mftData)) {
		return nil, fmt.Errorf("record for inode %d is outside MFT bounds", inode)
	}
	return v.readFileData(mftData[recStart:recEnd])
}

// FindChildInode returns the inode of the entry named name directly under parentInode.
func FindChildInode(mftData []byte, parentInode uint64, name string, recordSize uint64) (uint64, error) {
	return findChildInode(mftData, parentInode, name, recordSize)
}

// FindChildrenMatchingFiles returns files directly under parentInode that match pattern.

func FindChildrenMatchingFiles(mftData []byte, parentInode uint64, pattern string, recordSize uint64) []MatchEntry {
	return findChildrenMatching(mftData, parentInode, pattern, recordSize, false)
}

// FindChildrenMatchingDirs returns directories directly under parentInode that match pattern.

func FindChildrenMatchingDirs(mftData []byte, parentInode uint64, pattern string, recordSize uint64) []MatchEntry {
	return findChildrenMatching(mftData, parentInode, pattern, recordSize, true)
}

// findChildrenMatching is the internal implementation; dirsOnly=true returns only directories, false returns only files.
func findChildrenMatching(
	mftData []byte,
	parentInode uint64,
	pattern string,
	recordSize uint64,
	dirsOnly bool,
) []MatchEntry {
	totalRecords := uint64(len(mftData)) / recordSize
	var found []MatchEntry

	for i := uint64(0); i < totalRecords; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]

		if !isValidFileRecord(record) {
			continue
		}
		if len(record) < 0x18 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue // unused entry
		}
		isDir := flags&0x02 != 0
		if dirsOnly && !isDir {
			continue // skip directories when collecting files only
		}
		if !dirsOnly && isDir {
			continue // skip files when collecting directories only
		}

		if fname := getFileNameIfParent(record, parentInode); fname != "" {
			if wildcardMatch(pattern, fname) {
				found = append(found, MatchEntry{Name: fname, Inode: i})
			}
		}
	}
	return found
}

// wildcardMatch performs shell-style wildcard matching (* = any sequence, ? = any single char).
// Case-insensitive.
func wildcardMatch(pattern, name string) bool {
	p := []rune(strings.ToLower(pattern))
	n := []rune(strings.ToLower(name))
	return wildcardMatchInner(p, n)
}

func wildcardMatchInner(p, n []rune) bool {
	if len(p) == 0 {
		return len(n) == 0
	}
	switch p[0] {
	case '*':
		// match zero or more characters
		return wildcardMatchInner(p[1:], n) ||
			(len(n) > 0 && wildcardMatchInner(p, n[1:]))
	case '?':
		return len(n) > 0 && wildcardMatchInner(p[1:], n[1:])
	default:
		return len(n) > 0 && p[0] == n[0] && wildcardMatchInner(p[1:], n[1:])
	}
}

// getFileNameIfParent scans $FILE_NAME attributes (0x30) and returns
// the Win32-preferred filename if the parent inode matches.
// Returns empty string if no match.
func getFileNameIfParent(record []byte, parentInode uint64) string {
	if len(record) < 0x18 {
		return ""
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	type candidate struct {
		ns   uint8
		name string
	}
	var best *candidate

	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}

		if attrType == 0x30 {
			if pos+0x16 > len(record) {
				pos += attrLen
				continue
			}
			contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			cs := pos + contentOffset

			if cs+0x42 > len(record) {
				pos += attrLen
				continue
			}

			parRef := binary.LittleEndian.Uint64(record[cs : cs+8])
			par := parRef & 0x0000FFFFFFFFFFFF

			if par != parentInode {
				pos += attrLen
				continue
			}

			nameLen := int(record[cs+0x40])
			ns := record[cs+0x41] // 0=POSIX 1=Win32 2=DOS 3=Win32&DOS
			nameStart := cs + 0x42
			nameEnd := nameStart + nameLen*2
			if nameEnd > len(record) {
				pos += attrLen
				continue
			}

			utf16 := make([]uint16, nameLen)
			for i := range utf16 {
				utf16[i] = binary.LittleEndian.Uint16(record[nameStart+i*2:])
			}
			fname := windows.UTF16ToString(utf16)

			rank := func(n uint8) int {
				if n == 1 || n == 3 {
					return 2
				} else if n == 2 {
					return 1
				}
				return 0
			}
			if best == nil || rank(ns) > rank(best.ns) {
				best = &candidate{ns: ns, name: fname}
			}
		}
		pos += attrLen
	}
	if best == nil {
		return ""
	}
	return best.name
}

// ── MFT Session (with cache) ────────────────────────────────────────────────────

// FileEntry holds information about one file found during MFT scanning.
type FileEntry struct {
	RelPath string // volume-relative path (e.g. "Windows\System32\config\SYSTEM")
	Inode   uint64
}

// Session loads the MFT once and caches it, accelerating multi-file collection.
type Session struct {
	Label      string
	handle     *VolumeHandle
	mftData    []byte
	recordSize uint64
}

// NewSession opens the volume, loads the MFT once, and returns a Session.
func NewSession(volume string) (*Session, error) {
	handle, err := Open(volume)
	if err != nil {
		return nil, fmt.Errorf("failed to open volume: %w", err)
	}
	mftData, err := handle.ReadMFT()
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("MFT load failed: %w", err)
	}
	return &Session{
		Label:      volume,
		handle:     handle,
		mftData:    mftData,
		recordSize: handle.BytesPerFileRecord(),
	}, nil
}

// Close closes the session.
func (s *Session) Close() {
	s.handle.Close()
}

// ListDirEntries returns a list of FileEntry items under dirRelPath from the MFT.
// When recursive=true, subdirectories are also enumerated.
// Filenames are read from the MFT, so special characters are handled accurately.
func (s *Session) ListDirEntries(dirRelPath string, recursive bool) ([]FileEntry, error) {
	var dirInode uint64
	if dirRelPath == "" {
		dirInode = 5
	} else {
		var err error
		dirInode, err = findInodeByPath(s.mftData, dirRelPath, s.recordSize)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve directory inode (%s): %w", dirRelPath, err)
		}
	}
	var results []FileEntry
	s.listEntriesRecursive(dirInode, dirRelPath, recursive, &results)
	return results, nil
}

func (s *Session) listEntriesRecursive(dirInode uint64, dirRelPath string, recursive bool, out *[]FileEntry) {
	total := uint64(len(s.mftData)) / s.recordSize
	for i := uint64(0); i < total; i++ {
		start := i * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			break
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue
		}
		fname := getFileNameIfParent(record, dirInode)
		if fname == "" {
			continue
		}
		actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))
		isDir := flags&0x02 != 0
		relPath := joinSessionPath(dirRelPath, fname)
		if isDir {
			if recursive {
				s.listEntriesRecursive(actualInode, relPath, true, out)
			}
		} else {
			*out = append(*out, FileEntry{RelPath: relPath, Inode: actualInode})
		}
	}
}

// ListUserDirs returns subdirectory names and inodes directly under the Users directory.
func (s *Session) ListUserDirs(usersRelPath string) ([]FileEntry, error) {
	var dirInode uint64
	if usersRelPath == "" {
		dirInode = 5
	} else {
		var err error
		dirInode, err = findInodeByPath(s.mftData, usersRelPath, s.recordSize)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve Users directory: %w", err)
		}
	}
	total := uint64(len(s.mftData)) / s.recordSize
	var dirs []FileEntry
	for i := uint64(0); i < total; i++ {
		start := i * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			break
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 || flags&0x02 == 0 {
			continue
		}
		fname := getFileNameIfParent(record, dirInode)
		if fname == "" {
			continue
		}
		actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))
		dirs = append(dirs, FileEntry{RelPath: fname, Inode: actualInode})
	}
	return dirs, nil
}

// ReadFileByInode reads file data by inode number using the MFT cache.
func (s *Session) ReadFileByInode(inode uint64) ([]byte, error) {
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return nil, fmt.Errorf("record for inode %d not found in MFT", inode)
	}
	return s.readFileDataWithAttrList(record)
}

// readFileDataWithAttrList reads file data honoring $ATTRIBUTE_LIST.
func (s *Session) readFileDataWithAttrList(record []byte) ([]byte, error) {
	runs, realSize, err := s.collectDataRuns(record)
	if err != nil {
		return nil, err
	}
	if len(runs) > 0 {
		var out []byte
		for _, run := range runs {
			offset := run.LCN * s.handle.bytesPerCluster
			length := run.Clusters * s.handle.bytesPerCluster
			chunk, err := s.handle.readRaw(offset, length)
			if err != nil {
				return nil, err
			}
			out = append(out, chunk...)
			if realSize > 0 && uint64(len(out)) >= realSize {
				break
			}
		}
		if realSize > 0 && uint64(len(out)) > realSize {
			out = out[:realSize]
		}
		return out, nil
	}
	// resident data
	return getResidentData(record)
}

// GetFileSizeByInode returns the logical size of a file ($DATA size) in bytes by inode.
// Used to detect template EVTX files and other zero-content files.
func (s *Session) GetFileSizeByInode(inode uint64) (uint64, error) {
	record, err := s.findRecordByInode(inode)
	if err != nil {
		return 0, err
	}
	return getDataSize(record), nil
}

// findRecordByInode returns the MFT record for a given actual inode number.
func (s *Session) findRecordByInode(inode uint64) ([]byte, error) {
	// fast path
	recStart := inode * s.recordSize
	recEnd := recStart + s.recordSize
	if recEnd <= uint64(len(s.mftData)) {
		record := s.mftData[recStart:recEnd]
		if isValidFileRecord(record) && len(record) >= 0x30 {
			if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
				return record, nil
			}
		}
	}
	// linear scan
	total := uint64(len(s.mftData)) / s.recordSize
	for i := uint64(0); i < total; i++ {
		start := i * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			break
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		if uint64(binary.LittleEndian.Uint32(record[0x2C:0x30])) == inode {
			return record, nil
		}
	}
	return nil, fmt.Errorf("inode %d not found", inode)
}

// getDataSize returns the logical size of the $DATA attribute from an MFT record.
// Returns content length for resident data, or the Real Size field for non-resident data.
func getDataSize(record []byte) uint64 {
	if len(record) < 0x18 {
		return 0
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x80 { // $DATA
			nonResident := record[pos+8]
			if nonResident == 0 {
				// resident: +0x10 = content length (4B)
				if pos+0x14 <= len(record) {
					return uint64(binary.LittleEndian.Uint32(record[pos+0x10 : pos+0x14]))
				}
			} else {
				// non-resident: +0x30 = Real Size (8B)
				if pos+0x38 <= len(record) {
					return binary.LittleEndian.Uint64(record[pos+0x30 : pos+0x38])
				}
			}
		}
		pos += attrLen
	}
	return 0
}

// ReadFileByRelPath resolves path to inode and reads the file data using the MFT cache.
func (s *Session) ReadFileByRelPath(relPath string) ([]byte, error) {
	if strings.EqualFold(relPath, "$MFT") {
		return s.mftData, nil
	}
	inode, err := findInodeByPath(s.mftData, relPath, s.recordSize)
	if err != nil {
		return nil, err
	}
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return nil, fmt.Errorf("record for inode %d not found (path=%s)", inode, relPath)
	}
	return s.readFileDataWithAttrList(record)
}

// FileTimestamps holds file times extracted from an MFT record.
type FileTimestamps struct {
	Created  time.Time
	Modified time.Time // last modified time ($STANDARD_INFORMATION mTime)
	Accessed time.Time
	Changed  time.Time // MFT changed time (cTime)
}

// GetFileTimestampsByInode returns timestamps from $STANDARD_INFORMATION for the given inode.
// NTFS timestamps are 100-nanosecond intervals since 1601-01-01 UTC.
func (s *Session) GetFileTimestampsByInode(inode uint64) (FileTimestamps, bool) {
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return FileTimestamps{}, false
	}
	return extractTimestamps(record)
}

// extractTimestamps reads timestamps from the $STANDARD_INFORMATION attribute (0x10).
// $STANDARD_INFORMATION layout:
//
//	+0x00: Created time (8B)
//	+0x08: Modified time (8B)
//	+0x10: MFT changed time (8B)
//	+0x18: Accessed time (8B)
//
// Times are Windows FILETIME (100ns intervals, epoch 1601-01-01 UTC)
func extractTimestamps(record []byte) (FileTimestamps, bool) {
	if len(record) < 0x18 {
		return FileTimestamps{}, false
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset
	for pos+8 <= len(record) {
		attrType := binary.LittleEndian.Uint32(record[pos : pos+4])
		if attrType == 0xFFFFFFFF {
			break
		}
		attrLen := int(binary.LittleEndian.Uint32(record[pos+4 : pos+8]))
		if attrLen == 0 || pos+attrLen > len(record) {
			break
		}
		if attrType == 0x10 { // $STANDARD_INFORMATION
			nonRes := record[pos+8]
			if nonRes != 0 {
				break // $SI is always resident
			}
			contOff := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			cs := pos + contOff
			if cs+0x20 > len(record) {
				break
			}
			return FileTimestamps{
				Created:  filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x00 : cs+0x08])),
				Modified: filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x08 : cs+0x10])),
				Changed:  filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x10 : cs+0x18])),
				Accessed: filetimeToTime(binary.LittleEndian.Uint64(record[cs+0x18 : cs+0x20])),
			}, true
		}
		pos += attrLen
	}
	return FileTimestamps{}, false
}

// filetimeToTime converts a Windows FILETIME (100ns, epoch 1601-01-01 UTC) to time.Time.
func filetimeToTime(ft uint64) time.Time {
	// Windows FILETIME epoch: 1601-01-01 00:00:00 UTC
	// Unix epoch:             1970-01-01 00:00:00 UTC
	// Difference: 11644473600 seconds
	const epochDiff = 11644473600
	sec := int64(ft/10000000) - epochDiff
	nsec := int64((ft % 10000000) * 100)
	return time.Unix(sec, nsec).UTC()
}

// FindFileInode resolves a path to its inode number. Used for existence checks.
func (s *Session) FindFileInode(relPath string) (uint64, bool) {
	inode, err := findInodeByPath(s.mftData, relPath, s.recordSize)
	if err != nil {
		return 0, false
	}
	return inode, true
}

func joinSessionPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + `\` + name
}
