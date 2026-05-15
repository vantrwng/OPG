import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from spec_parser import SpecParser

p = SpecParser('crapi-openapi-spec.json')
ops = p.extract_operations()

targets = ['get_orders', 'convert_profile_video', 'create_order', 'get_vehicles']
for op in ops:
    if op['id'] not in targets:
        continue
    print(f"\n=== {op['id']} ({op['method']}) ===")
    print(f"  OUTPUTS ({len(op['outputs'])}):")
    for k, v in list(op['outputs'].items())[:6]:
        cn = v.get('contextual_name', '-')
        jp = v.get('json_path', '-')
        parent = v.get('parent', '-')
        print(f"    key={k!r:20} contextual={cn!r:20} path={jp!r:30} parent={parent!r}")
