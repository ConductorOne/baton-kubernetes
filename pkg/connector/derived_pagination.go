package connector

import "sort"

// pageBounds locates one page of a list this connector derives from live cluster
// state, resuming after the last key emitted rather than from an index.
//
// An index does not survive the cross-process resume the rest of this connector
// is built for. A resumed sync rebuilds the derived list from current cluster
// state, so if any entry sorting before the index disappeared meanwhile,
// everything after it shifts down and whichever entry lands on the old index is
// never emitted — silently, because nothing errors. Resuming from the first entry
// after a recorded key is self-correcting: entries appearing or disappearing
// before the cursor change which entries remain, not which are skipped.
//
// after is nil on the first page. sortsAfter reports whether an item sorts
// strictly after the recorded key, which is what makes the resume land on the
// next entry rather than repeat the last one; it must agree with the ordering the
// caller sorted by, or paging can skip or repeat entries.
//
// Returns the half-open range to emit. When end is short of len(items) the caller
// encodes items[end-1] as the next page token.
func pageBounds[T any, K any](items []T, after *K, size int, sortsAfter func(K, T) bool) (int, int) {
	start := 0
	if after != nil {
		start = sort.Search(len(items), func(i int) bool { return sortsAfter(*after, items[i]) })
	}
	end := len(items)
	if limit := pageLimit(size); start+limit < end {
		end = start + limit
	}
	return start, end
}
