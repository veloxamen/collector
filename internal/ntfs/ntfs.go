//go:build windows

// Package ntfs provides direct access to NTFS volume data by parsing raw structures.
package ntfs

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	fileFlagNoBuffering = 0x20000000
	fileFlagBackupSem   = 0x02000000
	genericRead         = 0x80000000
	fileShareReadWrite  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	fsctlGetNtfsVolData = 0x00090064 // FSCTL_GET_NTFS_VOLUME_DATA
)

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

// VolumeHandle represents an open NTFS volume and its associated geometry.
type VolumeHandle struct {
	handle             windows.Handle
	bytesPerSector     uint64
	bytesPerCluster    uint64
	mftStartLCN        uint64
	bytesPerFileRecord uint64
}

// Open initializes a connection to the raw NTFS volume.
func Open(volume string) (*VolumeHandle, error) {
	vol := strings.TrimRight(volume, `\`)
	// Handle volume strings like "C" or "C:" by ensuring a colon suffix.
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

// Close releases the volume handle.
func (v *VolumeHandle) Close() {
	windows.CloseHandle(v.handle)
}

// rawBufPool provides a pool of reusable byte slices to minimize allocations during raw disk reads.
var rawBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1<<20) // initial cap 1 MiB; grows on demand
		return &b
	},
}

// readRaw reads a specified number of bytes at a given offset, handling sector alignment automatically.
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

	// Borrow a buffer from the pool; grow it if the required size is larger.
	bufPtr := rawBufPool.Get().(*[]byte)
	if uint64(cap(*bufPtr)) < rawLen {
		*bufPtr = make([]byte, rawLen)
	}
	buf := (*bufPtr)[:rawLen]

	var bytesRead uint32
	err = windows.ReadFile(v.handle, buf, &bytesRead, nil)
	if err != nil && err != syscall.ERROR_HANDLE_EOF {
		rawBufPool.Put(bufPtr)
		return nil, fmt.Errorf("ReadFile failed offset=%d len=%d: %w", alignedOffset, rawLen, err)
	}

	available := uint64(bytesRead)
	if prefix > available {
		rawBufPool.Put(bufPtr)
		return nil, fmt.Errorf("readRaw: prefix(%d) exceeds bytesRead(%d) at alignedOffset=%d (sector=%d)",
			prefix, available, alignedOffset, sector)
	}
	end := prefix + length
	if end > available {
		end = available // EOF 付近のクリップ
	}
	// Return copy of slice, not reference, to avoid reading old data.
	result := make([]byte, end-prefix)
	copy(result, buf[prefix:end])
	rawBufPool.Put(bufPtr)
	return result, nil
}

// readFileRecord retrieves the MFT file record for the specified inode number.
func (v *VolumeHandle) readFileRecord(inode uint64) ([]byte, error) {
	mftOffset := v.mftStartLCN * v.bytesPerCluster
	recordOffset := mftOffset + inode*v.bytesPerFileRecord
	return v.readRaw(recordOffset, v.bytesPerFileRecord)
}

// readMFTData retrieves the complete Master File Table by parsing the data runs of inode 0.
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

// applyUSAFixupToMFT iterates through MFT data and applies Update Sequence Array fixups to each valid record.
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

// readFileData retrieves file data from the disk.
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

type dataRun struct {
	LCN      uint64
	Clusters uint64
}

// applyUSAFixup restores the original data bytes overwritten by the NTFS Update Sequence Array.
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

// isValidFileRecord checks if the file record has the valid signature.
func isValidFileRecord(record []byte) bool {
	return len(record) >= 4 && string(record[0:4]) == "FILE"
}

// collectDataRuns aggregates all $DATA data runs, accounting for both resident attributes and attribute lists.
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

// scanAttrList parses an $ATTRIBUTE_LIST and collects all associated $DATA data runs.
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

// parseDataRuns extracts LCN data runs from the $DATA attribute of an MFT record.
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

// decodeDataRuns parses the NTFS data-run byte stream into absolute LCNs and cluster counts.
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

// lookupChild searches the childMap for name under parentInode.
func (s *Session) lookupChild(parentInode uint64, name string) (uint64, bool) {
	nameLower := strings.ToLower(name)
	for _, e := range s.childMap[parentInode] {
		if e.name == nameLower {
			return e.inode, true
		}
	}
	return 0, false
}

// resolvePathInode resolves a volume-relative path to its corresponding inode using the indexed child map.
func (s *Session) resolvePathInode(relPath string) (uint64, error) {
	components := splitPath(relPath)
	parentInode := uint64(5) // NTFS root is always inode 5
	for _, component := range components {
		inode, ok := s.lookupChild(parentInode, component)
		if !ok {
			return 0, fmt.Errorf("'%s' not found (parent inode=%d)", component, parentInode)
		}
		parentInode = inode
	}
	return parentInode, nil
}

// resolvePathInodeWithFallback はまず childMap でパスを解決し、失敗した場合は
// MFT を全件スキャンしてファイル名の完全一致 → buildFullPath でフルパス照合する。
//
// $Recycle.Bin 配下のファイルのように、MFT の $FILE_NAME が指す親 inode が
// ファイルシステム API（filepath.Glob）の結果と乖離している場合に使用する。
func (s *Session) resolvePathInodeWithFallback(relPath string) (uint64, error) {
	inode, err := s.resolvePathInode(relPath)
	if err == nil {
		return inode, nil
	}

	// フォールバック: ファイル名でMFTを絞り込み、buildFullPathで照合
	log.Printf("[INFO] childMap miss, fallback scan for %q", relPath)
	components := splitPath(relPath)
	if len(components) == 0 {
		return 0, err
	}
	targetName := strings.ToLower(components[len(components)-1])

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
		_, fname, ok := extractBestFileName(record)
		if !ok || strings.ToLower(fname) != targetName {
			continue
		}
		fullPath, ok := s.buildFullPath(i)
		if ok && strings.EqualFold(fullPath, relPath) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("cannot resolve inode for %s (fallback exhausted)", relPath)
}

// extractBestFileNameWithAttrList retrieves $FILE_NAME From the $ATTRIBUTE_LIST(0x20)
// if the Win32 name is not found in the same record and is delegated to $ATTRIBUTE_LIST.
func (s *Session) extractBestFileNameWithAttrList(record []byte) (parentInode uint64, fname string, ok bool) {
	// Try to retrieve from the same record.
	parentInode, fname, ok = extractBestFileName(record)
	// Determine as OK if the Win32/Win32&DOS(rank=2) is retrieved.
	if ok {
		// Check the namespace if it has rank=2 (not a DOS shorten name).
		if !isDOSOnly(record) {
			return
		}
	}

	// Search external record via $ATTRIBUTE_LIST(0x20).
	attrListData := getAttributeListData(record)
	if len(attrListData) == 0 {
		// non-resident $ATTRIBUTE_LIST を読む
		attrListData = s.readNonResidentAttrList(record)
	}
	if len(attrListData) == 0 {
		return
	}

	// Search $ATTRIBUTE_LIST to find $FILE_NAME(0x30) entry.
	for pos := 0; pos+26 <= len(attrListData); {
		attrType := binary.LittleEndian.Uint32(attrListData[pos : pos+4])
		entryLen := int(binary.LittleEndian.Uint16(attrListData[pos+4 : pos+6]))
		if entryLen == 0 {
			break
		}
		if attrType == 0x30 { // $FILE_NAME
			ref := binary.LittleEndian.Uint64(attrListData[pos+0x10 : pos+0x18])
			extInode := ref & 0x0000FFFFFFFFFFFF
			extRecord := getRecordByInode(s.mftData, extInode, s.recordSize)
			if extRecord != nil {
				if p, n, o := extractBestFileName(extRecord); o && !isDOSOnly(extRecord) {
					return p, n, true
				}
			}
		}
		pos += entryLen
	}
	return
}

// isDOSOnly identifies that $FILE_NAME in a record has DOS(2) only.
func isDOSOnly(record []byte) bool {
	if len(record) < 0x18 {
		return true
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
		if attrType == 0x30 {
			contentOffset := int(binary.LittleEndian.Uint16(record[pos+0x14 : pos+0x16]))
			cs := pos + contentOffset
			if cs+0x42 <= len(record) {
				ns := record[cs+0x41]
				if ns == 1 || ns == 3 { // Win32 or Win32&DOS
					return false
				}
			}
		}
		pos += attrLen
	}
	return true
}

// readNonResidentAttrList reads non-resident $ATTRIBUTE_LIST data.
func (s *Session) readNonResidentAttrList(record []byte) []byte {
	runs := findAttributeListRuns(record)
	if len(runs) == 0 {
		return nil
	}
	// sentinel {0,0} は resident を示す（getAttributeListData で取得済み）
	if runs[0].LCN == 0 && runs[0].Clusters == 0 {
		return nil
	}
	data, err := s.readRunsRaw(runs)
	if err != nil {
		return nil
	}
	return data
}

// buildFullPath reconstructs the absolute path by traversing $FILE_NAME entries from the inode to the root.
func (s *Session) buildFullPath(inode uint64) (string, bool) {
	const maxDepth = 32
	parts := make([]string, 0, 8)
	current := inode
	for depth := 0; depth < maxDepth; depth++ {
		if current == 5 { // NTFS root
			break
		}
		start := current * s.recordSize
		end := start + s.recordSize
		if end > uint64(len(s.mftData)) {
			return "", false
		}
		record := s.mftData[start:end]
		if !isValidFileRecord(record) {
			return "", false
		}
		parentInode, fname, ok := s.extractBestFileNameWithAttrList(record)
		if !ok {
			return "", false
		}
		parts = append(parts, fname)
		current = parentInode
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, `\`), true
}

// checkFileNameAttr checks $FILE_NAME attributes (0x30) against parent inode and filename.
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

// splitPath converts a path string to a slice of path items.
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

// ChildrenMatchingFiles returns files under parentInode matching pattern using the childMap.
func (s *Session) ChildrenMatchingFiles(parentInode uint64, pattern string) []MatchEntry {
	return s.childrenMatchingFromMap(parentInode, pattern, false)
}

// ChildrenMatchingDirs returns directories under parentInode matching pattern using the childMap.
func (s *Session) ChildrenMatchingDirs(parentInode uint64, pattern string) []MatchEntry {
	return s.childrenMatchingFromMap(parentInode, pattern, true)
}

// childrenMatchingFromMap is the childMap-backed implementation.
func (s *Session) childrenMatchingFromMap(parentInode uint64, pattern string, dirsOnly bool) []MatchEntry {
	var found []MatchEntry
	for _, e := range s.childMap[parentInode] {
		if dirsOnly && !e.isDir {
			continue
		}
		if !dirsOnly && e.isDir {
			continue
		}
		if wildcardMatch(pattern, e.name) {
			found = append(found, MatchEntry{Name: e.name, Inode: e.inode})
		}
	}
	return found
}

// wildcardMatch performs a case-insensitive, shell-style wildcard match supporting '*' and '?'.
func wildcardMatch(pattern, name string) bool {
	p := []rune(strings.ToLower(pattern))
	n := []rune(strings.ToLower(name))
	np, nn := len(p), len(n)

	// row[j] = true means p[:i] matches n[:j] for the current pattern index i.
	row := make([]bool, nn+1)
	nxt := make([]bool, nn+1)

	row[0] = true // empty pattern matches empty name
	for i := 1; i <= np; i++ {
		for j := range nxt {
			nxt[j] = false
		}
		// nxt[0]: only '*' (matching zero chars) can extend a match to empty name.
		if p[i-1] == '*' {
			nxt[0] = row[0]
		}
		for j := 1; j <= nn; j++ {
			switch p[i-1] {
			case '*':
				// Either consume one name char (nxt[j-1]) or skip the '*' (row[j]).
				nxt[j] = nxt[j-1] || row[j]
			case '?':
				nxt[j] = row[j-1]
			default:
				nxt[j] = row[j-1] && p[i-1] == n[j-1]
			}
		}
		row, nxt = nxt, row
	}
	return row[nn]
}

// getFileNameIfParent retrieves the Win32-preferred filename for a record
// if it belongs to the specified parent inode.
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

// FileEntry holds information about one file found during MFT scanning.
type FileEntry struct {
	RelPath string // volume-relative path (e.g. "Windows\System32\config\SYSTEM")
	Inode   uint64
}

// childEntry is one entry in the childMap index.
type childEntry struct {
	name  string // Win32-preferred filename (lowercased for lookup)
	inode uint64
	isDir bool
}

// Session loads the MFT once and caches it, accelerating multi-file collection.
type Session struct {
	Label      string
	handle     *VolumeHandle
	mftData    []byte
	recordSize uint64
	childMap   map[uint64][]childEntry // parentInode → child entries
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
	recordSize := handle.BytesPerFileRecord()
	s := &Session{
		Label:      volume,
		handle:     handle,
		mftData:    mftData,
		recordSize: recordSize,
		childMap:   buildChildMap(mftData, recordSize),
	}
	log.Printf("[INFO] childMap built: %d parent inodes indexed", len(s.childMap))
	return s, nil
}

// buildChildMap constructs an index of parent-to-child relationships for fast path resolution.
func buildChildMap(mftData []byte, recordSize uint64) map[uint64][]childEntry {
	totalRecords := uint64(len(mftData)) / recordSize
	// Pre-allocate with a rough estimate to avoid repeated map growth.
	cm := make(map[uint64][]childEntry, totalRecords/4)

	for i := uint64(0); i < totalRecords; i++ {
		start := i * recordSize
		end := start + recordSize
		if end > uint64(len(mftData)) {
			break
		}
		record := mftData[start:end]

		if !isValidFileRecord(record) || len(record) < 0x30 {
			continue
		}
		flags := binary.LittleEndian.Uint16(record[0x16:0x18])
		if flags&0x01 == 0 {
			continue // not in-use
		}
		isDir := flags&0x02 != 0
		actualInode := uint64(binary.LittleEndian.Uint32(record[0x2C:0x30]))

		// Extract the best (Win32-preferred) filename and its parent inode.
		parentInode, fname, ok := extractBestFileName(record)
		if !ok || fname == "" {
			continue
		}
		cm[parentInode] = append(cm[parentInode], childEntry{
			name:  strings.ToLower(fname),
			inode: actualInode,
			isDir: isDir,
		})
	}
	return cm
}

// extractBestFileName reads all $FILE_NAME (0x30) attributes from a record and
// returns the parent inode and the Win32-preferred filename.
func extractBestFileName(record []byte) (uint64, string, bool) {
	if len(record) < 0x18 {
		return 0, "", false
	}
	attrsOffset := int(binary.LittleEndian.Uint16(record[0x14:0x16]))
	pos := attrsOffset

	type candidate struct {
		parentInode uint64
		name        string
		rank        int
	}
	var best *candidate

	nsRank := func(ns uint8) int {
		switch ns {
		case 1, 3:
			return 2 // Win32, Win32&DOS — preferred
		case 0:
			return 1 // POSIX
		default:
			return 0 // DOS
		}
	}

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
			nameLen := int(record[cs+0x40])
			ns := record[cs+0x41]
			nameStart := cs + 0x42
			nameEnd := nameStart + nameLen*2
			if nameEnd > len(record) {
				pos += attrLen
				continue
			}

			utf16 := make([]uint16, nameLen)
			for j := range utf16 {
				utf16[j] = binary.LittleEndian.Uint16(record[nameStart+j*2:])
			}
			fname := windows.UTF16ToString(utf16)
			r := nsRank(ns)
			if best == nil || r > best.rank {
				best = &candidate{parentInode: par, name: fname, rank: r}
			}
		}
		pos += attrLen
	}

	if best == nil {
		return 0, "", false
	}
	return best.parentInode, best.name, true
}

// Close closes the session.
func (s *Session) Close() {
	s.handle.Close()
}

// ListDirEntries returns a list of FileEntry items under dirRelPath from the MFT.
func (s *Session) ListDirEntries(dirRelPath string, recursive bool) ([]FileEntry, error) {
	var dirInode uint64
	if dirRelPath == "" {
		dirInode = 5
	} else {
		var err error
		dirInode, err = s.resolvePathInode(dirRelPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve directory inode (%s): %w", dirRelPath, err)
		}
	}
	var results []FileEntry
	s.listEntriesRecursive(dirInode, dirRelPath, recursive, &results)
	return results, nil
}

// listEntriesRecursive searches for child entries recursively.
func (s *Session) listEntriesRecursive(dirInode uint64, dirRelPath string, recursive bool, out *[]FileEntry) {
	// childMap lookup: O(children of dirInode) instead of O(entire MFT).
	for _, e := range s.childMap[dirInode] {
		relPath := joinSessionPath(dirRelPath, e.name)
		if e.isDir {
			if recursive {
				s.listEntriesRecursive(e.inode, relPath, true, out)
			}
		} else {
			*out = append(*out, FileEntry{RelPath: relPath, Inode: e.inode})
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
		dirInode, err = s.resolvePathInode(usersRelPath)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve Users directory: %w", err)
		}
	}
	// Use childMap: only iterate children of dirInode, not the entire MFT.
	var dirs []FileEntry
	for _, e := range s.childMap[dirInode] {
		if !e.isDir {
			continue
		}
		dirs = append(dirs, FileEntry{RelPath: e.name, Inode: e.inode})
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
		// Pre-allocate with the known real size to avoid repeated append growth.
		var out []byte
		if realSize > 0 {
			out = make([]byte, 0, realSize)
		}
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
	inode, err := s.resolvePathInodeWithFallback(relPath)
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
func (s *Session) GetFileTimestampsByInode(inode uint64) (FileTimestamps, bool) {
	record := getRecordByInode(s.mftData, inode, s.recordSize)
	if record == nil {
		return FileTimestamps{}, false
	}
	return extractTimestamps(record)
}

// extractTimestamps reads timestamps from the $STANDARD_INFORMATION attribute (0x10).
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
	inode, err := s.resolvePathInodeWithFallback(relPath)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// joinSessionPath joins a parent directory and a child node name.
func joinSessionPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + `\` + name
}
