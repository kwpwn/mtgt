import struct, re

with open("E:/ECAgent.exe", "rb") as f:
    data = f.read()

strings = re.findall(rb'[\x20-\x7e]{6,}', data)
wstrings = re.findall(rb'(?:[\x20-\x7e]\x00){6,}', data)
wstrings_dec = [s.decode('utf-16-le', 'replace') for s in wstrings]
all_str = [s.decode('latin-1') for s in strings] + wstrings_dec

def match(s, keys):
    sl = s.lower()
    return any(k in sl for k in keys)

categories = {
    'URL/HOST':    lambda s: match(s, ['http','https','://','127.0.0','localhost','sangfor','ssl','vpn','port']),
    'Command':     lambda s: match(s, ['cmd','exec','command','shell','run','launch','execute','payload','upgrade']),
    'Auth':        lambda s: match(s, ['auth','token','password','login','user','session','secret','encrypt','key','cert']),
    'Protocol':    lambda s: match(s, ['json','xml','request','response','method','post','get','header','content-type','packet','magic','length','size']),
    'FilePath':    lambda s: ('\\' in s or s.startswith('/')) and len(s) > 8 and '<' not in s,
    'Error/Log':   lambda s: match(s, ['error','fail','success','debug','log','warn','exception','connect','listen','socket','timeout']),
    'Registry':    lambda s: match(s, ['hkey','hklm','hkcu','software\\','system\\','registry']),
    'Version/ID':  lambda s: match(s, ['version','sangfor','build','release','agent','client','server']),
}

for cat, fn in categories.items():
    seen = set()
    unique = []
    for s in all_str:
        s2 = s.strip()
        if s2 not in seen and len(s2) >= 6 and fn(s2):
            seen.add(s2)
            unique.append(s2)
    if unique:
        print(f"\n=== {cat} ({len(unique)}) ===")
        for s in unique[:50]:
            print(f"  {repr(s)}")
