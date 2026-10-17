from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]
files=list(root.rglob('*.sql'))
text=(root/'Full Code Implementation/SmartBankDB_Codebase.sql').read_text(encoding='utf-8-sig')
controls={'database baseline':r'CREATE\s+DATABASE\s+SmartBankDB','temporal history':r'SYSTEM_VERSIONING\s*=\s*ON','roles':r'CREATE\s+ROLE','session identity':r'SESSION_CONTEXT','native audit':r'CREATE\s+SERVER\s+AUDIT','encrypted backups':r'ENCRYPTION','procedure layer':r'CREATE\s+(?:OR\s+ALTER\s+)?PROCEDURE'}
for name,pattern in controls.items():
    assert re.search(pattern,text,re.I),name
    print('Source contains:',name)
assert (root/'Full Code Implementation/SmartBankDB_FeatureTests.sql').exists()
print('SQL source files:',len(files))
print('PASS: static feature/source inventory. These text checks do not parse T-SQL or execute its security controls.')
print('NOT RUN: deployment, per-role permission tests, backup/restore, audit output or concurrency tests.')
