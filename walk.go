package main

// Structural HashMap walk for Burp .burp proxy-history.
//
// Chain (empirical, validated on 256 MB and 9.4 GB files):
//
//   header @0x40            -> u64 BE = catalog row offset (0xFA in both files)
//   catalog (15-col NodeCompact)     -> col 1 (tableId 1) = u64 BE -> ProxyHistoryRoot root (0x41c)
//   ProxyHistoryRoot (6-col NodeCompact)         -> 4 hashRoot ptrs (col 0..3), col 4 u32 = total size
//                              col 0 is canonical (== ProxyHistoryRoot.col4 size).
//   HashMapNode  (4-col NodeCompact)        -> col 2 = u64 -> bucket-desc row
//   bucket-desc (2-col NodeCompact)  -> col 1 = u64 -> level-1 chunk
//   level-1 chunk           [u32 totalLen][u32 N][N x u64 -> level-2]
//   level-2 chunk           [u32 totalLen][u32 count][count x u64 rowPtr]
//
// Each non-zero rowPtr is a ProxyRowFormat/ProxyRowFormat-style 31-col NodeCompact row whose:
//   row+0xaf  u64 BE = REQ  HttpChunk chunk header offset (col[15] tid=15)
//   row+0xc7  u64 BE = RESP HttpChunk chunk header offset (col[18] tid=18, 0 if absent)
// (row+0x69/0x71 are SubFieldEnvelope envelope ptrs to UTF-16 method/url sub-fields,
//  NOT direct chunk ptrs — earlier spec was wrong.)
//
// Validated counts:

import (
	"encoding/binary"
	"fmt"
	"os"
)

// proxyRow points to one HashMap leaf row. Both fields are file offsets of
// HttpChunk chunk headers (NOT row offsets). resp may be 0 if entry has no
// response captured (in-flight or aborted request).
type proxyRow struct {
	rowOff  uint64 // 31-col NodeCompact row base offset (for diagnostics)
	reqOff  uint64 // HttpChunk chunk header offset
	respOff uint64 // HttpChunk chunk header offset, 0 if absent
}

// walkProxyHistory traverses the structural HashMap chain from the file
// header to enumerate every proxy-history row pointer. Returns nil if the
// chain cannot be parsed (caller should fall back to chunk scan).
//
// Side effects: when GlobalVerbose is true, writes layer-by-layer trace to
// stderr.
func walkProxyHistory(data []byte) []proxyRow {
	n := uint64(len(data))
	if n < 0x48 {
		return nil
	}
	catalogPtr := binary.BigEndian.Uint64(data[0x40:0x48])
	if GlobalVerbose {
		fmt.Fprintf(os.Stderr, "walk: catalogPtr=0x%x n=%d\n", catalogPtr, n)
	}
	if !inFile(catalogPtr, n) {
		if GlobalVerbose {
			fmt.Fprintln(os.Stderr, "walk: catalogPtr out of range")
		}
		return nil
	}

	cat := parseNodeCompactRow(data, catalogPtr)
	if GlobalVerbose {
		fmt.Fprintf(os.Stderr, "walk: catalog parsed %d cols\n", len(cat.cols))
	}
	if len(cat.cols) < 2 {
		return nil
	}

	// ProxyHistoryRoot root = catalog.col1 (tableId 1). If unset, scan for first ptr-shaped col.
	var proxyHistoryRootPtr uint64
	if c := cat.cols[1]; c.width >= 8 && inFile(c.val, n) {
		proxyHistoryRootPtr = c.val
	} else {
		for _, c := range cat.cols {
			if c.width >= 8 && inFile(c.val, n) {
				proxyHistoryRootPtr = c.val
				break
			}
		}
	}
	if proxyHistoryRootPtr == 0 {
		return nil
	}

	proxyHistoryRoot := parseNodeCompactRow(data, proxyHistoryRootPtr)
	if len(proxyHistoryRoot.cols) < 5 {
		return nil
	}
	if GlobalVerbose {
		fmt.Fprintf(os.Stderr, "walk: ProxyHistoryRoot @ 0x%x, %d cols\n", proxyHistoryRootPtr, len(proxyHistoryRoot.cols))
		for i, c := range proxyHistoryRoot.cols {
			fmt.Fprintf(os.Stderr, "  col[%d] tid=%d relOff=0x%x w=%d val=0x%x\n",
				i, c.tid, c.relOff, c.width, c.val)
		}
	}

	// hashRoots = cols with 8-byte ptr in-file value. size/secondary = scalar cols.
	var hashRoots []uint64
	var size uint32
	for _, c := range proxyHistoryRoot.cols {
		if c.width >= 8 && inFile(c.val, n) {
			hashRoots = append(hashRoots, c.val)
			continue
		}
		if size == 0 && c.valU32 != 0 {
			size = c.valU32
		}
	}
	if len(hashRoots) == 0 {
		return nil
	}
	if GlobalVerbose {
		fmt.Fprintf(os.Stderr, "walk: hashRoots=%v size=%d\n", hexList(hashRoots), size)
	}

	// Walk every hashRoot; the canonical proxy index is the one whose rowPtr
	// count == ProxyHistoryRoot size. Other hashRoots are secondary indices (host map etc).
	var canonical []uint64
	var bestDelta uint64 = ^uint64(0)
	for _, hr := range hashRoots {
		ptrs := walkHashMapTree(data, hr)
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "walk: hashRoot 0x%x -> %d rowPtrs\n", hr, len(ptrs))
		}
		if uint32(len(ptrs)) == size && size > 0 {
			canonical = ptrs
			break
		}
		// size may be stale (entries deleted but counter not decremented).
		// Pick the hashmap whose count is closest to the stored size rather than
		// the largest — secondary indices (host maps) can be larger than the
		// primary proxy-history index and their rows lack req/resp chunk pointers.
		if size > 0 {
			var delta uint64
			if uint64(len(ptrs)) > uint64(size) {
				delta = uint64(len(ptrs)) - uint64(size)
			} else {
				delta = uint64(size) - uint64(len(ptrs))
			}
			if delta < bestDelta {
				bestDelta = delta
				canonical = ptrs
			}
		} else if len(ptrs) > len(canonical) {
			canonical = ptrs
		}
	}
	if len(canonical) == 0 {
		return nil
	}
	if GlobalVerbose && size > 0 && uint32(len(canonical)) != size {
		fmt.Fprintf(os.Stderr, "walk: size mismatch: stored=%d actual=%d (deleted entries)\n", size, len(canonical))
	}

	// Resolve req/resp chunk offsets per row.
	// col[15] tid=15 @ relOff 0x00af = REQ chunk ptr (HttpChunk header offset)
	// col[18] tid=18 @ relOff 0x00c7 = RESP chunk ptr (0 if no resp)
	// Validated via colmap cross-reference against scanChunks resp/req sets.
	// Note: row+0x69/0x71 are SubFieldEnvelope envelope ptrs to UTF-16 sub-fields
	// (method/url strings), NOT direct chunk ptrs.
	out := make([]proxyRow, 0, len(canonical))
	for i, rp := range canonical {
		// Parse fdir per row to find req/resp chunk ptrs by typeId.
		// relOff varies per row; hardcoded offsets (0xaf/0xc7) only work for
		// rows whose preceding cols happen to have the same widths. Scanning
		// by typeId is correct for all row shapes.
		//   tid=15 (HttpEntry req)  → HttpChunk chunk header offset for HTTP request
		//   tid=18 (HttpEntry resp) → HttpChunk chunk header offset for HTTP response
		// Validated empirically via colmap cross-reference on both files.
		row := parseNodeCompactRow(data, rp)
		var reqOff, respOff uint64
		for _, c := range row.cols {
			switch c.tid {
			case 15:
				reqOff = c.val
			case 18:
				respOff = c.val
			}
		}
		if GlobalVerbose && i < 3 {
			fmt.Fprintf(os.Stderr, "walk: row[%d] @0x%x reqOff=0x%x respOff=0x%x\n", i, rp, reqOff, respOff)
		}
		out = append(out, proxyRow{rowOff: rp, reqOff: reqOff, respOff: respOff})
	}
	return out
}

// walkHashMapTree descends HashMapNode -> bucket-desc -> level-1 -> level-2.
func walkHashMapTree(data []byte, vbRoot uint64) []uint64 {
	n := uint64(len(data))
	vb := parseNodeCompactRow(data, vbRoot)
	if len(vb.cols) < 3 {
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "  hashmap 0x%x: vbRoot too few cols (%d)\n", vbRoot, len(vb.cols))
		}
		return nil
	}
	// bucket-desc ptr = first 8-byte col with sane in-file value.
	var bdPtr uint64
	for _, c := range vb.cols {
		if c.width >= 8 && inFile(c.val, n) {
			bdPtr = c.val
			break
		}
	}
	if bdPtr == 0 {
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "  hashmap 0x%x: no bdPtr found in vb cols\n", vbRoot)
		}
		return nil
	}
	bd := parseNodeCompactRow(data, bdPtr)
	if len(bd.cols) < 2 {
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "  hashmap 0x%x: bd @0x%x too few cols (%d)\n", vbRoot, bdPtr, len(bd.cols))
		}
		return nil
	}
	l1Ptr := bd.cols[1].val
	if !inFile(l1Ptr, n) || l1Ptr+8 > n {
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "  hashmap 0x%x: l1Ptr=0x%x out of range\n", vbRoot, l1Ptr)
		}
		return nil
	}
	l1TotalLen := binary.BigEndian.Uint32(data[l1Ptr : l1Ptr+4])
	l1N := binary.BigEndian.Uint32(data[l1Ptr+4 : l1Ptr+8])
	if GlobalVerbose {
		fmt.Fprintf(os.Stderr, "  hashmap 0x%x: l1Ptr=0x%x totalLen=%d l1N=%d\n", vbRoot, l1Ptr, l1TotalLen, l1N)
	}
	if l1N == 0 || l1N > 1<<20 {
		if GlobalVerbose {
			fmt.Fprintf(os.Stderr, "  hashmap 0x%x: l1N=%d rejected (0 or >1M)\n", vbRoot, l1N)
		}
		return nil
	}
	var (
		ptrs             []uint64
		skippedL2Zero    int
		skippedL2OOB     int
		skippedL2NZero   int
		skippedL2NTooBig int
		skippedRPZero    int
		skippedRPOOB     int
		l1OOB            int
	)
	for i := uint32(0); i < l1N; i++ {
		ePos := l1Ptr + 8 + uint64(i)*8
		if ePos+8 > n {
			l1OOB++
			break
		}
		l2Ptr := binary.BigEndian.Uint64(data[ePos : ePos+8])
		if l2Ptr == 0 {
			skippedL2Zero++
			continue
		}
		if !inFile(l2Ptr, n) || l2Ptr+8 > n {
			skippedL2OOB++
			if GlobalVerbose {
				fmt.Fprintf(os.Stderr, "  hashmap 0x%x: l1[%d] l2Ptr=0x%x OOB\n", vbRoot, i, l2Ptr)
			}
			continue
		}
		l2TotalLen := binary.BigEndian.Uint32(data[l2Ptr : l2Ptr+4])
		l2N := binary.BigEndian.Uint32(data[l2Ptr+4 : l2Ptr+8])
		_ = l2TotalLen
		if l2N == 0 {
			skippedL2NZero++
			continue
		}
		if l2N > 1<<20 {
			skippedL2NTooBig++
			if GlobalVerbose {
				fmt.Fprintf(os.Stderr, "  hashmap 0x%x: l1[%d] l2Ptr=0x%x l2N=%d too big (totalLen=%d)\n", vbRoot, i, l2Ptr, l2N, l2TotalLen)
			}
			continue
		}
		for j := uint32(0); j < l2N; j++ {
			rPos := l2Ptr + 8 + uint64(j)*8
			if rPos+8 > n {
				break
			}
			rp := binary.BigEndian.Uint64(data[rPos : rPos+8])
			if rp == 0 {
				skippedRPZero++
				continue
			}
			if !inFile(rp, n) {
				skippedRPOOB++
				if GlobalVerbose {
					fmt.Fprintf(os.Stderr, "  hashmap 0x%x: l1[%d] l2[%d] rp=0x%x OOB\n", vbRoot, i, j, rp)
				}
				continue
			}
			ptrs = append(ptrs, rp)
		}
	}
	if GlobalVerbose {
		fmt.Fprintf(os.Stderr, "  hashmap 0x%x: collected=%d skipped: l2zero=%d l2oob=%d l2Nzero=%d l2Nbig=%d rpZero=%d rpOOB=%d l1OOB=%d\n",
			vbRoot, len(ptrs), skippedL2Zero, skippedL2OOB, skippedL2NZero, skippedL2NTooBig, skippedRPZero, skippedRPOOB, l1OOB)
	}
	return ptrs
}

// ---------- NodeCompact node parsing ----------

type nodeField struct {
	tid    uint8
	relOff uint16
	width  int    // 4 or 8 (inferred from gap to next col; terminal defaults 8)
	val    uint64 // 4-byte cols zero-extended
	valU32 uint32 // first 4 bytes (always populated)
}

type node struct {
	off  uint64
	cols []nodeField
}

// parseNodeCompactRow decodes count_byte @ off+3, fdir @ off+4 (3-byte entries
// `[typeId u8][relOff u16 BE]`), and reads each col's value at off+relOff.
// Width is inferred from the gap to the next col; the terminal col defaults
// to 8 bytes (most tail cols are pointers).
func parseNodeCompactRow(data []byte, off uint64) node {
	n := uint64(len(data))
	if off+4 > n {
		return node{off: off}
	}
	count := int(data[off+3])
	if count == 0 || count > 64 {
		return node{off: off}
	}
	cols := make([]nodeField, count)
	fdir := off + 4
	for i := 0; i < count; i++ {
		base := fdir + uint64(i*3)
		if base+3 > n {
			return node{off: off}
		}
		cols[i].tid = data[base]
		cols[i].relOff = binary.BigEndian.Uint16(data[base+1 : base+3])
	}
	for i := 0; i < count; i++ {
		var w int
		if i+1 < count {
			w = int(cols[i+1].relOff - cols[i].relOff)
		} else {
			w = 8
		}
		cols[i].width = w
		coff := off + uint64(cols[i].relOff)
		if coff+4 <= n {
			cols[i].valU32 = binary.BigEndian.Uint32(data[coff : coff+4])
		}
		if w >= 8 && coff+8 <= n {
			cols[i].val = binary.BigEndian.Uint64(data[coff : coff+8])
		} else {
			cols[i].val = uint64(cols[i].valU32)
		}
	}
	return node{off: off, cols: cols}
}

func inFile(v, n uint64) bool { return v >= 0x48 && v < n }

func hexList(vs []uint64) string {
	s := ""
	for i, v := range vs {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("0x%x", v)
	}
	return s
}
