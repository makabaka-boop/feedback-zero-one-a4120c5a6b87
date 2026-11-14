"""Self-written matching engine.

Events are fed in op order.  On demand the engine computes the set of all
matches over the events arrived so far.  A match is a tuple of event
indices, strictly increasing by (t, id), all sharing one key, with
last.t - first.t <= span.  Matches are keyed by their id tuple, which
deduplicates identical id sequences arising from different derivations.

Concatenation (seq, and adjacent repetitions of rep) requires:
  * same key;
  * right's first event strictly after left's last event by (t, id)
    (hence no event reuse across the whole match);
  * time difference within the closed interval g;
  * no raw event of the same key whose type is in b with t strictly
    between the two boundary times (unselected recovery events negate).
"""

from bisect import bisect_right, insort


class _Event:
    __slots__ = ("eid", "key", "etype", "t")

    def __init__(self, eid, key, etype, t):
        self.eid = eid
        self.key = key
        self.etype = etype
        self.t = t


class Engine:
    def __init__(self, span, pattern):
        self.span = span
        self.pattern = pattern
        self.events = []        # arrival order
        self._type_times = {}   # key -> {type: sorted [t, ...]}
        self._cache_n = -1
        self._cache = None

    def add_event(self, eid, key, etype, t):
        self.events.append(_Event(eid, key, etype, t))
        times = self._type_times.setdefault(key, {}).setdefault(etype, [])
        insort(times, t)

    def matches(self):
        """All current matches: {id_tuple: event_index_tuple}."""
        if self._cache_n != len(self.events):
            self._cache = self._node(self.pattern)
            self._cache_n = len(self.events)
        return self._cache

    def _node(self, node):
        tag = node[0]
        if tag == "leaf":
            etype = node[1]
            out = {}
            for i, e in enumerate(self.events):
                if e.etype == etype:
                    out[(e.eid,)] = (i,)
            return out
        if tag == "or":
            out = self._node(node[1])
            for ids, tup in self._node(node[2]).items():
                out.setdefault(ids, tup)
            return out
        if tag == "seq":
            left = self._node(node[1])
            right = self._node(node[2])
            return self._concat(left, right, node[3], node[4])
        # ("rep", P, m, n, g, b): matches of exactly k repetitions, m <= k <= n
        _, sub, m, n, g, blockers = node
        base = self._node(sub)
        out = {}
        limit = min(n, len(self.events))  # each repetition consumes >= 1 event
        acc = base                        # matches of exactly k repetitions
        k = 1
        while acc and k <= limit:
            if k >= m:
                for ids, tup in acc.items():
                    out.setdefault(ids, tup)
            if k == limit:
                break
            acc = self._concat(acc, base, g, blockers)
            k += 1
        return out

    def _concat(self, left, right, g, blockers):
        glo, ghi = g
        span = self.span
        events = self.events
        right_by_key = {}
        for rids, rtup in right.items():
            right_by_key.setdefault(events[rtup[0]].key, []).append((rids, rtup))
        out = {}
        for lids, ltup in left.items():
            last = events[ltup[-1]]
            start_t = events[ltup[0]].t
            for rids, rtup in right_by_key.get(last.key, ()):
                head = events[rtup[0]]
                dt = head.t - last.t
                if dt < glo or dt > ghi:
                    continue
                # strictly increasing by (t, id); dt >= glo >= 0 always
                if dt == 0 and head.eid <= last.eid:
                    continue
                # durations only grow when extended: prune beyond span early
                if events[rtup[-1]].t - start_t > span:
                    continue
                if self._blocked(last.key, last.t, head.t, blockers):
                    continue
                out.setdefault(lids + rids, ltup + rtup)
        return out

    def _blocked(self, key, t1, t2, blockers):
        """Any raw event of this key, type in blockers, t in open (t1, t2)?"""
        if not blockers:
            return False
        per_key = self._type_times.get(key)
        if not per_key:
            return False
        for etype in blockers:
            times = per_key.get(etype)
            if not times:
                continue
            i = bisect_right(times, t1)
            if i < len(times) and times[i] < t2:
                return True
        return False


def execute(span, pattern, ops):
    """Run the validated ops; return the output array (one batch per
    watermark op, empty batches kept)."""
    engine = Engine(span, pattern)
    output = []
    watermark = -1
    for op in ops:
        if op[0] == "event":
            engine.add_event(op[1], op[2], op[3], op[4])
            continue
        w = op[1]
        batch = []
        for ids, tup in engine.matches().items():
            first = engine.events[tup[0]]
            start = first.t
            # publish exactly once, when the watermark first reaches
            # or exceeds start + span
            if watermark < start + span <= w:
                batch.append({
                    "key": first.key,
                    "ids": list(ids),
                    "start": start,
                    "end": engine.events[tup[-1]].t,
                })
        batch.sort(key=lambda item: (item["key"], item["ids"]))
        output.append(batch)
        watermark = w
    return output
