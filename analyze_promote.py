import struct, re

with open("E:/SangforPromoteService.exe", "rb") as f:
    data = f.read()

strings = re.findall(rb'[\x20-\x7e]{5,}', data)
wstrings = re.findall(rb'(?:[\x20-\x7e]\x00){5,}', data)
wstrings_dec = [s.decode('utf-16-le', 'replace') for s in wstrings]
all_str = [s.decode('latin-1') for s in strings] + wstrings_dec

def match(s, keys):
    sl = s.lower()
    return any(k in sl for k in keys)

print("=== Sangfor/ECAgent specific ===")
sangfor = [s for s in all_str if match(s, ['sangfor','ecagent','ecbase','promote','54530','sslusr','session','ecagent'])]
seen = set()
for s in sangfor:
    s2 = s.strip()
    if s2 not in seen and len(s2) >= 5:
        seen.add(s2)
        print(f"  {repr(s2)}")

print()
print("=== Protocol / HTTP / JSON ===")
proto = [s for s in all_str if match(s, ['http','websocket','json','result','message','debug','callback','127.0.0','op=','token','upgrade','switch'])]
seen2 = set()
for s in proto:
    s2 = s.strip()
    if s2 not in seen2 and len(s2) >= 5:
        seen2.add(s2)
        print(f"  {repr(s2)}")

print()
print("=== Registry / COM ===")
reg_keys = ['hklm','hkcu','software\\\\','clsid','progid','sangfor','dispatch','createinstance']
com = [s for s in all_str if match(s, reg_keys)]
seen3 = set()
for s in com:
    s2 = s.strip()
    if s2 not in seen3 and len(s2) >= 5:
        seen3.add(s2)
        print(f"  {repr(s2)}")

print()
print("=== Format strings (potential overflow) ===")
fmts = [s for s in all_str if '%s' in s or '%d' in s or '%u' in s]
seen4 = set()
for s in fmts:
    s2 = s.strip()
    if s2 not in seen4 and len(s2) >= 5 and len(s2) < 300:
        seen4.add(s2)
        print(f"  {repr(s2)}")

print()
print("=== Error/debug log strings ===")
errs = [s for s in all_str if match(s, ['error','fail','success','warn','connect','listen','recv','send','parse','start','stop','init','load','open'])]
seen5 = set()
for s in errs:
    s2 = s.strip()
    if s2 not in seen5 and len(s2) >= 8:
        seen5.add(s2)
        print(f"  {repr(s2)}")
