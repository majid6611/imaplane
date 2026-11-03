#!/usr/bin/env python3
"""Synthetic-mail fixtures. Endpoints/credentials are pinned to this isolated lab."""
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
import hashlib
import imaplib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
import tomllib

LAB = Path('/lab')
FOLDERS = ['INBOX','Projects/Invoices','旅行/日本語','Archiv/Grüße','رسائل/العمل','Clients/📬 & "Quotes" \\ Notes']
PER_FOLDER = 20
TOTAL = PER_FOLDER * len(FOLDERS)

# RFC3501 modified UTF-7; fixture clients retain rev1 mode explicitly.
def utf7(text):
    result, run = '', ''
    def flush():
        return '&'+base64.b64encode(run.encode('utf-16be')).decode().rstrip('=').replace('/',',')+'-' if run else ''
    for ch in text:
        if ' ' <= ch <= '~':
            result += flush(); run = ''
            result += '&-' if ch == '&' else ch
        else: run += ch
    return result+flush()

def quote(name): return '"'+utf7(name).replace('\\','\\\\').replace('"','\\"')+'"'
def password(role): return f'test-only-{role}-password'
def context(): return ssl.create_default_context(cafile=str(LAB/'ca.pem'))
def connect(role):
    if role not in ['source','destination']: raise ValueError('Only isolated lab endpoints are allowed')
    client = imaplib.IMAP4_SSL(role,993,ssl_context=context(),timeout=15)
    client.login(f'{role}@imaplane.test',password(role))
    return client

def render_config(folders, state='./state/migration', proxy=False):
    text=f'state_dir = {json.dumps(state)}\ntimeout_seconds = 30\nmax_message_bytes = 67108864\nread_attempts = 3\n'
    for role in ['source','destination']:
        host='localhost' if proxy and role=='destination' else role
        port=19993 if proxy and role=='destination' else 993
        text+=f'\n[{role}]\nhost = "{host}"\nport = {port}\nusername = "{role}@imaplane.test"\npassword_file = "./{role}.password"\nca_file = "./ca.pem"\nsecurity = "tls"\nauth = "auto"\n'
    for source,destination in folders:
        text+=f'\n[[folders]]\nsource = {json.dumps(source,ensure_ascii=False)}\ndestination = {json.dumps(destination,ensure_ascii=False)}\n'
    return text

def write_json(path,data):
    path.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n'); path.chmod(0o600)

def validate_config(path,proxy=False,bad_ca=False):
    c=tomllib.loads(path.read_text())
    for role in ['source','destination']:
        endpoint=c[role]
        expected_host='localhost' if proxy and role=='destination' else role
        expected_port=19993 if proxy and role=='destination' else 993
        assert endpoint['host']==expected_host and endpoint['port']==expected_port, 'Non-lab endpoint rejected'
        assert endpoint['username']==f'{role}@imaplane.test'
        assert endpoint['auth']=='auto' and endpoint['security']=='tls'
        assert set(endpoint)=={'host','port','username','password_file','security','auth'} | (set() if bad_ca else {'ca_file'})
        assert (path.parent/endpoint['password_file']).resolve()==LAB/f'{role}.password'
        assert (LAB/f'{role}.password').read_text().strip()==password(role),'Non-test credential rejected'
        if not bad_ca: assert (path.parent/endpoint['ca_file']).resolve()==LAB/'ca.pem'
    assert (path.parent/c['state_dir']).resolve().is_relative_to(LAB/'state')
    assert {f['source'] for f in c['folders']}==set(FOLDERS)
    return c

def cli(action, path=LAB/'migration.toml', expected=0, name=None, flags=(), proxy=False,bad_ca=False):
    validate_config(path,proxy=proxy,bad_ca=bad_ca)
    result=subprocess.run(['/usr/local/bin/imaplane',action,'--config',str(path),*flags],capture_output=True,text=True,timeout=180)
    if name:
        (LAB/'reports'/f'{name}.stderr.log').write_text(result.stderr)
        (LAB/'reports'/f'{name}.stdout.json').write_text(result.stdout)
    if result.returncode!=expected:
        raise AssertionError(f'{action}: exit {result.returncode}, expected {expected}\n{result.stdout}\n{result.stderr}')
    for role in ['source','destination']:
        assert password(role) not in result.stdout+result.stderr
    return json.loads(result.stdout) if result.stdout else None

def existing(client,folder):
    result,data=client.select(quote(folder),readonly=True)
    return result=='OK'

def records(client,folder):
    assert client.select(quote(folder),readonly=True)[0]=='OK',folder
    validity=int(client.response('UIDVALIDITY')[1][0])
    status,values=client.uid('SEARCH',None,'ALL'); assert status=='OK'
    messages=[]
    for uid in values[0].split():
        status,data=client.uid('FETCH',uid,'(UID FLAGS INTERNALDATE BODY.PEEK[])'); assert status=='OK'
        items=[v for v in data if isinstance(v,tuple)]; assert len(items)==1
        header,body=items[0]
        flags=sorted(f.decode() for f in imaplib.ParseFlags(header) if f.lower()!=b'\\recent')
        date_raw=re.search(rb'INTERNALDATE "([^"]+)"',header).group(1).decode()
        instant=int(datetime.strptime(date_raw,'%d-%b-%Y %H:%M:%S %z').timestamp())
        messages.append({'uid':int(uid),'sha256':hashlib.sha256(body).hexdigest(),'size':len(body),'flags':flags,'date':instant})
    return {'uid_validity':validity,'messages':messages}

def snapshot(role,folders):
    client=connect(role)
    try: return {f:records(client,f) for f in folders}
    finally: client.logout()

def signatures(rows):
    return Counter((m['sha256'],m['size'],tuple(f.lower() for f in m['flags']),m['date']) for m in rows)

def pdf_bytes(number):
    content=f'BT /F1 12 Tf 40 100 Td (IMAPLANE test invoice {number:04d}) Tj ET'.encode()
    objects=[b'<< /Type /Catalog /Pages 2 0 R >>',b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
             b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 150] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
             b'<< /Length '+str(len(content)).encode()+b' >>\nstream\n'+content+b'\nendstream',
             b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    data=b'%PDF-1.4\n'; offsets=[0]
    for i,obj in enumerate(objects,1):
        offsets.append(len(data)); data+=f'{i} 0 obj\n'.encode()+obj+b'\nendobj\n'
    xref=len(data); data+=b'xref\n0 6\n0000000000 65535 f \n'
    data+=b''.join(f'{offset:010d} 00000 n \n'.encode() for offset in offsets[1:])
    return data+f'trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()

def generate(folder_index,index):
    number=folder_index*100+index
    message=EmailMessage(policy=SMTP)
    message['From']='Nora García <nora@sender.imaplane.test>'
    message['To']='Local Test User <source@imaplane.test>'
    message['Message-ID']=f'<fixture-{number:04d}@imaplane.test>'
    message['Subject']=f'Invoice {number:04d} — café, 日本語, مرحبا 📬'
    date=datetime(2024,1,1,9,30,tzinfo=timezone.utc)+timedelta(days=number)
    message['Date']=date
    message.set_content(f'Hello,\n\nSynthetic invoice {number:04d} for the local integration lab.\nこんにちは / Grüße / مرحبا\n\nNo real customer data. See the three attachments.\n')
    message.add_alternative(f'<html><body><h1>Test invoice {number:04d}</h1><p>こんにちは · Grüße · مرحبا</p><p>Synthetic lab data only.</p></body></html>',subtype='html')
    message.add_attachment(pdf_bytes(number),maintype='application',subtype='pdf',filename=f'invoice-{number:04d}.pdf')
    csv='item,description,amount\n'+''.join(f'{n},Test café item {n},{n*3}.50\n' for n in range(1,101))
    message.add_attachment(csv.encode(),maintype='text',subtype='csv',filename='détails-明細.csv')
    png=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jZQAAAABJRU5ErkJggg==')
    message.add_attachment(png,maintype='image',subtype='png',filename='logo.png')
    # Deterministic boundaries make the fixture bytes repeatable across resets.
    for part_number,part in enumerate(message.walk()):
        if part.is_multipart(): part.set_boundary(f'IMAPLANE-{number:04d}-{part_number}')
    flags=[]
    if index%2==0: flags.append('\\Seen')
    if index%5==0: flags.append('\\Flagged')
    if index%3==0: flags.append('\\Answered')
    if index==7: flags.append('\\Draft')
    flags.append('lab-fixture')
    return message.as_bytes(),flags,date

def seed():
    manifest=LAB/'manifest.json'
    if manifest.exists():
        check_source(); print('Existing 120-message fixture retained; no reseeding',flush=True); return
    source,destination=connect('source'),connect('destination')
    try:
        assert records(source,'INBOX')['messages']==[], 'Source is not empty; use lab reset'
        assert records(destination,'INBOX')['messages']==[], 'Destination is not empty; use lab reset'
        expected={}
        for folder_index,folder in enumerate(FOLDERS):
            if folder!='INBOX': assert source.create(quote(folder))[0]=='OK'
            originals=[generate(folder_index,i) for i in range(16)]
            for index in range(PER_FOLDER):
                body,flags,date=originals[index if index<16 else index-16]
                assert source.append(quote(folder),'('+' '.join(flags)+')',imaplib.Time2Internaldate(date),body)[0]=='OK'
            expected[folder]=records(source,folder)
            assert len(expected[folder]['messages'])==PER_FOLDER
        for i in range(3):
            body=f'From: existing@imaplane.test\r\nTo: destination@imaplane.test\r\nSubject: Preserve pre-existing {i}\r\n\r\nDestination baseline; never replace or delete.\r\n'.encode()
            assert destination.append('INBOX','(\\Seen)','"01-Jan-2023 00:00:00 +0000"',body)[0]=='OK'
        baseline=records(destination,'INBOX')
        write_json(manifest,{'format':1,'message_count':TOTAL,'source':expected,'destination_baseline':baseline,
                             'folders':FOLDERS,'attachments_per_message':3,'duplicates_per_folder':4})
        config=LAB/'migration.toml'; config.write_text(render_config([(f,f) for f in FOLDERS])); config.chmod(0o600)
        print('Seeded 120 emails, 360 attachment instances, 24 duplicate instances, 60 read and 60 unread messages',flush=True)
    finally: source.logout(); destination.logout()

def check_source():
    manifest=json.loads((LAB/'manifest.json').read_text())
    assert snapshot('source',FOLDERS)==manifest['source'], 'Source bytes/UIDs/dates/persistent flags changed'
    return manifest

def check_destination(prefix=''):
    manifest=check_source()
    destination=connect('destination')
    try:
        baseline=manifest['destination_baseline']
        actual_inbox=records(destination,'INBOX')
        old_uids={m['uid'] for m in baseline['messages']}
        assert actual_inbox['uid_validity']==baseline['uid_validity']
        assert [m for m in actual_inbox['messages'] if m['uid'] in old_uids]==baseline['messages'], 'Preexisting destination mail changed'
        for folder in FOLDERS:
            target=prefix+folder
            rows=records(destination,target)['messages']
            if not prefix and folder=='INBOX': rows=[m for m in rows if m['uid'] not in old_uids]
            expected=manifest['source'][folder]['messages']
            assert len(rows)==PER_FOLDER,(target,len(rows))
            assert signatures(rows)==signatures(expected),f'Content/date/flags/multiplicity mismatch in {target}'
    finally: destination.logout()
    return manifest

def test():
    manifest=check_source()
    discovered=cli('inspect',name='inspect')
    names={f['name'] for f in discovered['source'] if f['selectable']}
    assert set(FOLDERS)==names
    before=snapshot('destination',['INBOX'])
    state_existed=(LAB/'state/migration').exists()
    cli('migrate',name='dry-run',flags=['--dry-run'])
    assert snapshot('destination',['INBOX'])==before
    assert (LAB/'state/migration').exists()==state_existed, 'Dry-run created migration state'
    # Negative TLS trust test uses the same local hosts, with no custom lab CA.
    bad_path=LAB/'untrusted.toml'
    text=(LAB/'migration.toml').read_text().replace('ca_file = "./ca.pem"\n','')
    bad_path.write_text(text); bad_path.chmod(0o600)
    cli('inspect',bad_path,expected=1,name='untrusted-ca',bad_ca=True)
    first=cli('migrate',name='migration',flags=['--json'])
    assert first['complete'] and len(first['entries'])==TOTAL
    assert all(e['result']=='confirmed' and not e['omitted_flags'] for e in first['entries'])
    check_destination()
    after=snapshot('destination',FOLDERS)
    resumed=cli('migrate',name='resume',flags=['--json']); assert resumed['complete']
    assert snapshot('destination',FOLDERS)==after,'Resume appended duplicates'
    verified=cli('verify',name='verification',flags=['--json']); assert verified['complete']
    check_destination()
    after_names=cli('inspect',name='inspect-after')
    assert {f['name'] for f in after_names['source'] if f['selectable']}==set(FOLDERS)
    write_json(LAB/'reports/migration-test.json',{'passed':True,'source_messages':TOTAL,'normal_destination_messages':TOTAL+3,
               'attachment_instances':360,'read':60,'unread':60,'duplicate_instances':24,'source_unchanged':True,
               'resume_unchanged':True,'tls_negative_check':True})
    print('PASS: 120 exact transfers; 360 attachments; dates/flags/multiplicity; source unchanged; 3 preexisting messages preserved; verify/resume; untrusted CA rejected',flush=True)

def run_cli():
    action=sys.argv[2]
    flags=sys.argv[3:]
    allowed={'inspect':set(),'migrate':{'--dry-run','--json'},'verify':{'--json'},'status':{'--json'}}
    assert action in allowed and all(f in allowed[action] for f in flags), 'Non-lab CLI arguments rejected'
    validate_config(LAB/'migration.toml')
    args=['--state','/lab/state/migration/journal.sqlite3'] if action=='status' else ['--config','/lab/migration.toml']
    os.execv('/usr/local/bin/imaplane',['imaplane',action,*args,*flags])

if __name__=='__main__':
    try:
        if not __debug__: raise RuntimeError('Python optimization must be disabled for lab checks')
        action=sys.argv[1]
        if action=='seed': seed()
        elif action=='test': test()
        elif action=='cli': run_cli()
        elif action=='check': check_destination(); print('Source and migrated destination match manifest')
        else: raise ValueError('Unknown fixture command')
    except Exception as e:
        print(f'LAB FAILURE: {e}',file=sys.stderr); sys.exit(1)
