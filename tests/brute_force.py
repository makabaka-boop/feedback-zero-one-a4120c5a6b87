"""Independent brute-force reference used only by the acceptance tests.

It enumerates every candidate event sequence (all subsequences of each
key, strictly increasing by (t, id), duration <= span) and decides pattern
membership directly from the formal semantics -- sharing no code with the
engine in ``faultseg``.
"""

from itertools import combinations


class Ev:
    __slots__ = ("eid", "key", "etype", "t")

    def __init__(self, eid, key, etype, t):
        self.eid = eid
        self.key = key
        self.etype = etype
        self.t = t


def _blocked(events, key, t1, t2, blockers):
    for e in events:
        if e.key == key and e.etype in blockers and t1 < e.t < t2:
            return True
    return False


def matches_seq(seq, node, events):
    """Does the event-index sequence ``seq`` match pattern ``node``?

    ``seq`` is strictly increasing by (t, id) and single-key.
    """
    tag = node[0]
    if tag == "leaf":
        return len(seq) == 1 and events[seq[0]].etype == node[1]
    if tag == "or":
        return (matches_seq(seq, node[1], events)
                or matches_seq(seq, node[2], events))
    if tag == "seq":
        glo, ghi = node[3]
        blockers = node[4]
        for cut in range(1, len(seq)):
            a = events[seq[cut - 1]]
            c = events[seq[cut]]
            if not (glo <= c.t - a.t <= ghi):
                continue
            if _blocked(events, a.key, a.t, c.t, blockers):
                continue
            if (matches_seq(seq[:cut], node[1], events)
                    and matches_seq(seq[cut:], node[2], events)):
                return True
        return False
    # ("rep", P, m, n, g, b): some partition into k in [m, n] contiguous
    # parts, each matching P, adjacent parts satisfying the concat rule
    sub, m, n = node[1], node[2], node[3]
    glo, ghi = node[4]
    blockers = node[5]
    total = len(seq)
    if total < m:
        return False
    memo = {}

    def rec(pos, k):
        # can seq[pos:] be split into exactly k parts each matching sub?
        if k == 0:
            return pos == total
        if total - pos < k:
            return False
        if pos > 0:  # concat rule at the part boundary
            a = events[seq[pos - 1]]
            c = events[seq[pos]]
            if not (glo <= c.t - a.t <= ghi):
                return False
            if _blocked(events, a.key, a.t, c.t, blockers):
                return False
        state = (pos, k)
        if state not in memo:
            ok = False
            for end in range(pos + 1, total - k + 2):
                if matches_seq(seq[pos:end], sub, events) and rec(end, k - 1):
                    ok = True
                    break
            memo[state] = ok
        return memo[state]

    for k in range(m, min(n, total) + 1):
        if rec(0, k):
            return True
    return False


def all_matches(pattern, events, span):
    """All matches over ``events``: {id_tuple: output_item}."""
    by_key = {}
    for i, e in enumerate(events):
        by_key.setdefault(e.key, []).append(i)
    found = {}
    for key, idxs in by_key.items():
        idxs.sort(key=lambda i: (events[i].t, events[i].eid))
        for r in range(1, len(idxs) + 1):
            for combo in combinations(idxs, r):
                if events[combo[-1]].t - events[combo[0]].t > span:
                    continue
                if matches_seq(combo, pattern, events):
                    ids = tuple(events[i].eid for i in combo)
                    found[ids] = {
                        "key": events[combo[0]].key,
                        "ids": list(ids),
                        "start": events[combo[0]].t,
                        "end": events[combo[-1]].t,
                    }
    return found


def expected_output(span, pattern, ops):
    """Full expected output for validated IR ops, computed independently."""
    events = []
    out = []
    watermark = -1
    for op in ops:
        if op[0] == "event":
            events.append(Ev(op[1], op[2], op[3], op[4]))
        else:
            w = op[1]
            found = all_matches(pattern, events, span)
            batch = [item for item in found.values()
                     if watermark < item["start"] + span <= w]
            batch.sort(key=lambda item: (item["key"], item["ids"]))
            out.append(batch)
            watermark = w
    return out
