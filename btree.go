package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

// Burp "Ryt" engine layout (decoded from BurpEngine bytecode + probe verification):
//   offset 56: next_free  (uint64 BE) — allocator HWM
//   offset 64: root BTree (uint64 BE) — schema BTree root, typically 0xFA
//
// Multiple node formats (NodeFormat instances; (Zs=count_off, Zw=fdir_off)):
//   NodeCompact:        count@+3,  fdir@+4    (compact, used for most schema pages)
//   NodeSecondary:        count@+21, fdir@+22   (used for some BTree pages)
//   ProxyRow:  count@+31, fdir@+32   (proxy-history table rows)
//
// Each fdir entry is (typeId byte, int16 BE relOff). Field data lives at
// basePtr+relOff. Pointer columns are 8-byte uint64 BE values.

const (
	nodeCompactCountOffset = 3
	nodeCompactFdirStart   = 4
	nodeSecondaryCountOffset = 21
	nodeSecondaryFdirStart   = 22
	nodeCompactEntrySize   = 3
	maxBTreeDepth = 16

	// rowReqRelSig / rowRespRelSig: minimum invariant for proxy-history rows.
	// Memory's full 24-byte fdir is one schema variant; broader detection uses
	// just the (col4=req-blob-ptr, col5=resp-blob-ptr) pair appearing adjacent
	// in the fdir. This sub-signature catches all schema variants that share
	// the cols-4/5 blob layout.
)

// rowSubSig is the minimum proxy-history row signature: cols 4 and 5 with
// adjacent 8-byte ptr fields. col4 must be at relOff 0x38 (req blob ptr) and
// col5 at relOff 0x40 (resp blob ptr). Empirically this layout is invariant
// across all proxy-history rows seen in test files, even when cols 0..3 or
// 6..7 differ. Total = 6 bytes.
var rowSubSig = []byte{0x04, 0x00, 0x38, 0x05, 0x00, 0x40}

type nodeFormat struct {
	name        string
	countOffset int64
	fdirStart   int64
}

var (
	formatNodeCompact = nodeFormat{"NodeCompact", nodeCompactCountOffset, nodeCompactFdirStart}
	formatNodeSecondary = nodeFormat{"NodeSecondary", nodeSecondaryCountOffset, nodeSecondaryFdirStart}
)

type walkOpts struct {
	verbose bool
	maxRows int
}

// walkBTree starts at the file's BTree root and returns every row pointer
// reachable through NodeCompact/NodeSecondary-format nodes.
//
// In Burp's design, proxy-history rows are NOT reachable from this root;
// it indexes schema metadata only. Walker confirms structure but emits no
// rows. Use scanRows() for proxy-history extraction.
func walkBTree(data []byte, opts walkOpts) []int64 {
	if len(data) < 72 {
		return nil
	}
	rootPtr := int64(binary.BigEndian.Uint64(data[64:72]))
	if rootPtr <= 0 || rootPtr >= int64(len(data)) {
		return nil
	}

	w := &btreeWalker{
		data:    data,
		opts:    opts,
		visited: make(map[int64]bool),
	}
	w.walk(rootPtr, formatNodeCompact, 0)

	if opts.verbose {
		fmt.Fprintf(os.Stderr,
			"btree: root=0x%x  visited=%d  NodeCompact=%d  NodeSecondary=%d  rows=%d  unknown=%d\n",
			rootPtr, len(w.visited), w.nodeCompactCount, w.nodeSecondaryCount, len(w.rows), w.unknown)
	}
	return w.rows
}

type btreeWalker struct {
	data    []byte
	opts    walkOpts
	visited map[int64]bool
	rows    []int64
	nodeCompactCount int
	nodeSecondaryCount int
	unknown int
}

func (w *btreeWalker) walk(ptr int64, fmt_ nodeFormat, depth int) {
	if depth > maxBTreeDepth || ptr <= 0 || ptr+fmt_.fdirStart >= int64(len(w.data)) {
		return
	}
	key := ptr*4 + int64(len(fmt_.name))
	if w.visited[key] {
		return
	}
	w.visited[key] = true

	count := int(w.data[ptr+fmt_.countOffset])
	if count == 0 || count > 64 {
		return
	}
	fdirEnd := fmt_.fdirStart + nodeCompactEntrySize*int64(count)
	if ptr+fdirEnd > int64(len(w.data)) {
		return
	}
	switch fmt_.name {
	case "NodeCompact":
		w.nodeCompactCount++
	case "NodeSecondary":
		w.nodeSecondaryCount++
	}

	for i := 0; i < count; i++ {
		entryOff := ptr + fmt_.fdirStart + int64(i)*nodeCompactEntrySize
		relOff := int16(binary.BigEndian.Uint16(w.data[entryOff+1 : entryOff+3]))
		fieldOff := ptr + int64(relOff)
		if fieldOff < 0 || fieldOff+8 > int64(len(w.data)) {
			continue
		}
		childPtr := int64(binary.BigEndian.Uint64(w.data[fieldOff : fieldOff+8]))
		if childPtr <= 72 || childPtr >= int64(len(w.data)) {
			continue
		}
		w.classify(childPtr, depth+1)
		if w.opts.maxRows > 0 && len(w.rows) >= w.opts.maxRows {
			return
		}
	}
}

func (w *btreeWalker) classify(childPtr int64, depth int) {
	if w.isRow(childPtr) {
		w.rows = append(w.rows, childPtr)
		return
	}
	if w.isNode(childPtr, formatNodeCompact) {
		w.walk(childPtr, formatNodeCompact, depth)
		return
	}
	if w.isNode(childPtr, formatNodeSecondary) {
		w.walk(childPtr, formatNodeSecondary, depth)
		return
	}
	// Terminal payload — not a recognized inner node and not a proxy row.
	// Could be schema catalog row, blob, or unknown structure. Dump it.
	if GlobalDumpLeaves {
		w.dumpLeaf(childPtr)
	}
	w.unknown++
}

// dumpLeaf prints a candidate catalog/leaf node to stderr. Format:
//   leaf 0x<ptr>  prev64=<hex>  ascii=<printable>
// Caller has already determined childPtr is non-NodeCompact/NodeSecondary, non-row.
func (w *btreeWalker) dumpLeaf(ptr int64) {
	end := ptr + 128
	if end > int64(len(w.data)) {
		end = int64(len(w.data))
	}
	if ptr < 0 || ptr >= int64(len(w.data)) {
		return
	}
	chunk := w.data[ptr:end]
	// Hex dump first 64 bytes.
	hexBuf := make([]byte, 0, 192)
	for i, b := range chunk {
		if i >= 64 {
			break
		}
		const hexd = "0123456789abcdef"
		hexBuf = append(hexBuf, hexd[b>>4], hexd[b&0xf])
		if i%4 == 3 {
			hexBuf = append(hexBuf, ' ')
		}
	}
	// ASCII rendering of full 128 bytes.
	asciiBuf := make([]byte, 0, 128)
	for _, b := range chunk {
		if b >= 0x20 && b < 0x7f {
			asciiBuf = append(asciiBuf, b)
		} else {
			asciiBuf = append(asciiBuf, '.')
		}
	}
	fmt.Fprintf(os.Stderr, "leaf 0x%08x %s | %s\n", ptr, hexBuf, asciiBuf)
}

func (w *btreeWalker) isRow(childPtr int64) bool {
	// Proxy-history row test: cols 4 (req blob) and 5 (resp blob) must appear
	// at the canonical relOffs inside the row's fdir.
	start := childPtr + rowFdirOffset + 12 // skip first 4 fdir entries (cols 0-3)
	end := start + int64(len(rowSubSig))
	if start < 0 || end > int64(len(w.data)) {
		return false
	}
	return bytes.Equal(w.data[start:end], rowSubSig)
}

func (w *btreeWalker) isNode(childPtr int64, fmt_ nodeFormat) bool {
	if childPtr+fmt_.fdirStart >= int64(len(w.data)) {
		return false
	}
	count := int(w.data[childPtr+fmt_.countOffset])
	if count == 0 || count > 64 {
		return false
	}
	end := childPtr + fmt_.fdirStart + nodeCompactEntrySize*int64(count)
	return end <= int64(len(w.data))
}
