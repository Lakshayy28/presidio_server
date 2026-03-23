import json, pathlib, collections

results_dir = pathlib.Path('reports/allure-results')
failed = []
for f in results_dir.glob('*-result.json'):
    try:
        d = json.loads(f.read_text())
        if d.get('status') in ('failed', 'broken'):
            failed.append({
                'name': d.get('name',''),
                'status': d.get('status'),
                'msg': (d.get('statusDetails') or {}).get('message','')[:200],
                'trace': (d.get('statusDetails') or {}).get('trace','')[:400],
            })
    except Exception:
        pass

print(f'Total failed/broken: {len(failed)}')
print()
by_msg = collections.defaultdict(list)
for r in failed:
    key = r['msg'][:100]
    by_msg[key].append(r['name'])

for msg, names in sorted(by_msg.items(), key=lambda x: -len(x[1])):
    print(f'[{len(names)} tests] ERROR: {msg}')
    for n in names[:4]:
        print(f'   - {n}')
    if len(names) > 4:
        print(f'   ... and {len(names)-4} more')
    print()
