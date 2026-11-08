#!/usr/bin/env python3
"""Second, smaller set of Gmail de-duplication experiments (X1-X5), Python standard library only.

Same safety model as gmail_dedup_experiments.py: it talks ONLY to a confined-write guard proxy
(readonly_imap_proxy.py --confine-folder C --readonly-folder "[Gmail]/All Mail" --max-appends 10) and writes only to ONE new
label. At most 9 tiny synthetic messages are appended; an APPEND is never retried; nothing existing is read for writing, changed or
deleted. After every step it records the label, All Mail info and a Message-ID search (UID, X-GM-MSGID, flags, SHA-256 of the bytes).

  X1 same body, different Message-ID          (2 appends)
  X2 same Message-ID and body, Subject changed (2 appends; X2a is also the base of X3)
  X3 same Message-ID and body, Date changed    (1 append)
  X4 Message-ID upper-case variant, same body  (2 appends)
  X5 two identical messages without Message-ID (2 appends)
"""
import argparse, hashlib, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gmail_dedup_experiments import Session, build, D, ALL_MAIL

CAP = 9


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, required=True)
    ap.add_argument('--label', required=True)
    ap.add_argument('--token-file', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    os.makedirs(a.out, mode=0o700, exist_ok=True)
    s = Session(a.port, open(a.token_file).read().strip())
    log = open(os.path.join(a.out, 'steps2.jsonl'), 'a', buffering=1)
    os.chmod(os.path.join(a.out, 'steps2.jsonl'), 0o600)
    typ, boxes = s.c.list()
    if any(f'"{a.label}"' in b.decode() for b in boxes):
        sys.exit('REFUSED: the label already exists; will not write into a pre-existing label')
    typ, _ = s.c.create(f'"{a.label}"'); assert typ == 'OK'
    ids, done = [], []

    def snap(step, extra):
        rec = {'step': step, 'time': time.time(), 'label': s.label_view(a.label), 'allmail_info': s.examine(ALL_MAIL),
               'allmail_by_message_id': s.search_all_mail(ids)}
        rec.update(extra); log.write(json.dumps(rec) + '\n')
        n = len(rec['label']['messages'])
        print(f'{step}: append={extra["append_ok"]} label_messages={n} uids={[m["uid"] for m in rec["label"]["messages"]]}', flush=True)

    def do(step, flags, date, mid, body, subject='IMAPLANE dedup experiment', raw=None):
        assert len(done) < CAP, 'append budget reached'
        raw = raw if raw is not None else build(mid, body, date, subject)
        if mid is not None and mid not in ids:
            ids.append(mid)
        typ, resp = s.append(a.label, flags, date, raw)       # never retried
        done.append(step)
        time.sleep(7)                                          # Gmail needs 2-5 s before a new message is searchable
        snap(step, {'append_ok': typ, 'append_response': resp, 'sha256': hashlib.sha256(raw).hexdigest(), 'n_appended': len(done)})
        return raw

    snap('S0 after CREATE', {'append_ok': 'n/a'})
    T = 'IMAPLANE dedup experiment'
    do('X1a body=B1 id=x1a', '\\Seen', D(2021, 1, 1), '<x1a@example.invalid>', 'shared body for X1')
    do('X1b same body, id=x1b', '\\Flagged', D(2021, 1, 1), '<x1b@example.invalid>', 'shared body for X1')
    do('X2a base id=x2', '\\Seen', D(2021, 2, 1), '<x2@example.invalid>', 'body for X2/X3')
    do('X2b same id+body, Subject changed', '\\Flagged', D(2021, 2, 1), '<x2@example.invalid>', 'body for X2/X3', subject='A DIFFERENT SUBJECT')
    do('X3 same id+body, Date header changed', '\\Answered', D(2021, 2, 2), '<x2@example.invalid>', 'body for X2/X3')
    do('X4a id=x4', '\\Seen', D(2021, 3, 1), '<x4@example.invalid>', 'body for X4')
    do('X4b upper-case id, same body', '\\Flagged', D(2021, 3, 1), '<X4@EXAMPLE.INVALID>', 'body for X4')
    raw5 = build(None, 'no message id, identical twice', D(2021, 4, 1))
    do('X5a no id (first)', '\\Seen', D(2021, 4, 1), None, None, raw=raw5)
    do('X5b no id (identical bytes again)', '\\Seen', D(2021, 4, 1), None, None, raw=raw5)
    print('appends performed:', len(done), '(cap', CAP, ')')
    json.dump({'appended_steps': done, 'count': len(done)}, open(os.path.join(a.out, 'summary2.json'), 'w'))
    s.c.logout()


if __name__ == '__main__':
    main()
