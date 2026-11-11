"""Sistem Informasi WIB–SES Group · MVP internal (bukan produksi)."""
import os, re, io, json, csv, hmac, math, uuid, time, base64, hashlib, secrets, sqlite3, mimetypes, tempfile, zipfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from typing import Optional
from fastapi import FastAPI, Request, Response, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.colors import HexColor
import qrcode
import sk_wib, sk_ses, docx_sk, kta_card

BASE=Path(__file__).resolve().parent
DATA=Path(os.environ.get('WIB_DATA_DIR',str(BASE/'runtime'))); DATA.mkdir(parents=True,exist_ok=True)
PRIVATE=DATA/'uploads'; PRIVATE.mkdir(exist_ok=True)
SK_ASSETS=DATA/'sk_assets'; SK_ASSETS.mkdir(exist_ok=True)
SK_DOCX=SK_ASSETS/'template_sk_wib.docx'
PDF_CACHE=DATA/'sk_cache'
DB=DATA/'wib_ses.sqlite3'
SECRET_FILE=DATA/'.local_secret'
if not SECRET_FILE.exists(): SECRET_FILE.write_bytes(Fernet.generate_key()); os.chmod(SECRET_FILE,0o600)
KEY=SECRET_FILE.read_bytes(); CRYPT=Fernet(KEY)
TZ=timezone(timedelta(hours=7))
app=FastAPI(title='WIB–SES Group',version='1.1.0')
app.mount('/static',StaticFiles(directory=str(BASE/'static')),name='static')
ROLES=['superadmin','admin_wib','ketum','sekjen','waketum','dpw','ses_admin','ses_director','ses_pic','auditor','pengurus']
ORGS=['DPW','DPD','DPC','PAC']
SES_ROLE={'DPW':'Koordinator Wilayah','DPD':'Kepala Cabang','DPC':'Kepala Cabang','PAC':'Kepala Unit'}
DOC_TYPES=['ktp','kesbangpol','akta_ses_notariil','foto_depan','foto_dalam','alamat_kantor','banner_ses','akta_wib','ahu_wib','ad_art','npwp_wib','rencana_kerja','bukti_koordinasi','sk_wib','sk_ses','dokumen_keputusan','lainnya']
# Dokumen per tujuan. Salinan akta SES notarial adalah legalitas kantor/cabang SES, bukan dokumen pribadi pengurus
# (unggahan lama tetap tersimpan dan dapat diunduh).
PERSON_DOCS=['ktp','sk_wib','sk_ses','rencana_kerja','bukti_koordinasi','lainnya']
OFFICE_DOCS=['kesbangpol','akta_ses_notariil','foto_depan','foto_dalam','alamat_kantor','banner_ses','akta_wib','ahu_wib','ad_art','npwp_wib','lainnya']
APPOINTMENT_DOCS=['dokumen_keputusan','sk_wib','lainnya']
# Administrasi pengurus PIB (Partai Indonesia Bergerak). PIB_REQUIRED = berkas wajib untuk status lengkap.
PIB_REQUIRED=['ktp','pas_foto','kta_pib','pakta_integritas','surat_kesediaan','surat_bukan_parpol_lain','daftar_riwayat_hidup']
PIB_DOCS=PIB_REQUIRED+['surat_domisili','lainnya']
PIB_VIEWERS=['superadmin','admin_wib','dpw','ketum','sekjen','waketum','auditor']
PIB_EDITORS=['superadmin','admin_wib','dpw']
KTA_ENABLED=False  # Modul KTA ditunda pada V1.1; kode dan nomor anggota tetap dipertahankan
REPORT_REVIEWERS=['superadmin','ketum','sekjen','waketum']
REPORT_MONITORS=REPORT_REVIEWERS+['admin_wib','auditor','dpw']
SES_STEPS={'draft':'Draft','menunggu_ses':'Menunggu Persetujuan SES','perlu_perbaikan':'Perlu Perbaikan','ditolak':'Ditolak','menunggu_pengesahan':'Menunggu Pengesahan','disetujui':'Disetujui','sk_diterbitkan':'SK Diterbitkan'}
# Akun pengurus wilayah (Ketua/Sekretaris) hanya untuk laporan kegiatan wilayahnya sendiri.
PENGURUS_PATHS=('/api/me','/api/logout','/api/config','/api/reports','/api/account/password','/api/reference/')

def now(): return datetime.now(TZ).isoformat(timespec='seconds')
def today(): return datetime.now(TZ).date().isoformat()

def db():
 c=sqlite3.connect(str(DB),timeout=15,isolation_level=None,check_same_thread=False)
 c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=15000');return c
@contextmanager
def transaction():
 c=db()
 try:
  c.execute('BEGIN IMMEDIATE');yield c;c.commit()
 except: c.rollback();raise
 finally:c.close()

def rows(c,sql,args=()):return [dict(x) for x in c.execute(sql,args)]
def row(c,sql,args=()):
 r=c.execute(sql,args).fetchone();return dict(r) if r else None

def audit(c,actor,action,entity,ident,detail=''):
 c.execute('INSERT INTO audits(actor,action,entity,entity_id,detail,created_at) VALUES(?,?,?,?,?,?)',(actor,action,entity,ident,str(detail)[:800],now()))
def hashpass(p,salt=None):
 salt=salt or secrets.token_bytes(16);return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,250000).hex()
def checkpass(password,encoded):
 salt,expected=encoded.split(':');got=hashpass(password,bytes.fromhex(salt));return hmac.compare_digest(got,encoded)
def nik_hash(v):return hmac.new(KEY,v.encode(),hashlib.sha256).hexdigest()
def mask_phone(v):
 if not v:return '—'
 return v[:3]+'••••'+v[-3:] if len(v)>6 else '••••'
def safe_json(data): return json.dumps(data,ensure_ascii=False,separators=(',',':'))

def initialize():
 with transaction() as c:
  c.executescript('''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL, full_name TEXT NOT NULL, region TEXT, active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, phone TEXT, gender TEXT, address TEXT, nik_hash TEXT UNIQUE, nik_encrypted BLOB, nik_last4 TEXT, nik_status TEXT NOT NULL DEFAULT 'belum_diperiksa', photo_path TEXT, created_at TEXT NOT NULL, created_by INTEGER REFERENCES users(id), status TEXT NOT NULL DEFAULT 'draft');
CREATE TABLE IF NOT EXISTS appointments(id INTEGER PRIMARY KEY, person_id INTEGER NOT NULL REFERENCES people(id), level TEXT NOT NULL, province TEXT NOT NULL, city TEXT NOT NULL DEFAULT '', district TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', member_no TEXT, sk_no TEXT UNIQUE, started_at TEXT, ended_at TEXT, end_reason TEXT, created_at TEXT NOT NULL, approved_at TEXT, UNIQUE(person_id,level,province,city,district,title,started_at));
CREATE TABLE IF NOT EXISTS ses_assignments(id INTEGER PRIMARY KEY, person_id INTEGER NOT NULL REFERENCES people(id), wib_appointment_id INTEGER NOT NULL REFERENCES appointments(id), ses_role TEXT NOT NULL, region TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', sk_no TEXT UNIQUE, started_at TEXT, ended_at TEXT, last_verified_at TEXT, end_reason TEXT, created_at TEXT NOT NULL, approved_at TEXT, UNIQUE(wib_appointment_id));
CREATE TABLE IF NOT EXISTS offices(id INTEGER PRIMARY KEY, level TEXT NOT NULL, province TEXT NOT NULL, city TEXT NOT NULL DEFAULT '', district TEXT NOT NULL DEFAULT '', address TEXT NOT NULL DEFAULT '', pic_person_id INTEGER REFERENCES people(id), updated_at TEXT, UNIQUE(level,province,city,district));
CREATE TABLE IF NOT EXISTS documents(id INTEGER PRIMARY KEY, target_kind TEXT NOT NULL, target_id INTEGER NOT NULL, doc_type TEXT NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'menunggu', uploaded_by INTEGER NOT NULL REFERENCES users(id), uploaded_at TEXT NOT NULL, verified_by INTEGER REFERENCES users(id), verified_at TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS activities(id INTEGER PRIMARY KEY, track TEXT NOT NULL, person_id INTEGER NOT NULL REFERENCES people(id), appointment_id INTEGER, category TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', proof TEXT, status TEXT NOT NULL DEFAULT 'menunggu', occurred_at TEXT NOT NULL, created_at TEXT NOT NULL, verified_at TEXT, verified_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS opportunities(id INTEGER PRIMARY KEY, person_id INTEGER NOT NULL REFERENCES people(id), ses_assignment_id INTEGER REFERENCES ses_assignments(id), region TEXT NOT NULL, category TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', organization TEXT, estimated_value REAL, stage TEXT NOT NULL DEFAULT 'identifikasi', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evaluations(id INTEGER PRIMARY KEY, track TEXT NOT NULL, entity_id INTEGER NOT NULL, period TEXT NOT NULL, score INTEGER NOT NULL, result TEXT NOT NULL, notes TEXT, evaluator INTEGER REFERENCES users(id), created_at TEXT NOT NULL, UNIQUE(track,entity_id,period));
CREATE TABLE IF NOT EXISTS numbers(kind TEXT NOT NULL, year INTEGER NOT NULL, sequence INTEGER NOT NULL, PRIMARY KEY(kind,year));
CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY,actor INTEGER,action TEXT NOT NULL,entity TEXT NOT NULL,entity_id INTEGER,detail TEXT,created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_app_region ON appointments(province,city,status);
CREATE INDEX IF NOT EXISTS idx_docs_target ON documents(target_kind,target_id);
CREATE INDEX IF NOT EXISTS idx_activities_person ON activities(person_id,status);
CREATE TABLE IF NOT EXISTS sk_templates(track TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at TEXT, updated_by INTEGER REFERENCES users(id));
CREATE TABLE IF NOT EXISTS ses_reviews(id INTEGER PRIMARY KEY, assignment_id INTEGER NOT NULL REFERENCES ses_assignments(id), action TEXT NOT NULL, from_status TEXT, to_status TEXT NOT NULL, note TEXT, actor INTEGER REFERENCES users(id), actor_name TEXT, actor_role TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sk_numbers(track TEXT NOT NULL, sk_no TEXT NOT NULL, ref_id INTEGER, issued_at TEXT NOT NULL, PRIMARY KEY(track,sk_no));
CREATE TABLE IF NOT EXISTS sk_image_auth(slot TEXT PRIMARY KEY, sha1 TEXT NOT NULL, authorized_by INTEGER REFERENCES users(id), authorized_name TEXT, authorized_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activity_files(id INTEGER PRIMARY KEY, activity_id INTEGER NOT NULL REFERENCES activities(id), kind TEXT NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL, uploaded_by INTEGER REFERENCES users(id), uploaded_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_ses_reviews ON ses_reviews(assignment_id);
CREATE INDEX IF NOT EXISTS idx_activity_files ON activity_files(activity_id);
CREATE TABLE IF NOT EXISTS kta_cards(id INTEGER PRIMARY KEY, nomor TEXT NOT NULL, nama TEXT NOT NULL, jenis_kelamin TEXT NOT NULL, jabatan TEXT NOT NULL, tingkat TEXT NOT NULL, wilayah TEXT NOT NULL, provinsi TEXT NOT NULL DEFAULT '', terbit TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'aktif', cancel_note TEXT, created_by INTEGER REFERENCES users(id), created_at TEXT NOT NULL, updated_by INTEGER REFERENCES users(id), updated_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_kta_nomor_aktif ON kta_cards(nomor) WHERE status='aktif';
CREATE INDEX IF NOT EXISTS idx_kta_nomor ON kta_cards(nomor);
CREATE INDEX IF NOT EXISTS idx_app_person ON appointments(person_id);
CREATE INDEX IF NOT EXISTS idx_ses_person ON ses_assignments(person_id);
CREATE TABLE IF NOT EXISTS pib_members(id INTEGER PRIMARY KEY, person_id INTEGER NOT NULL REFERENCES people(id), wib_appointment_id INTEGER REFERENCES appointments(id), level TEXT NOT NULL, province TEXT NOT NULL, city TEXT NOT NULL DEFAULT '', district TEXT NOT NULL DEFAULT '', title TEXT NOT NULL, kta_no TEXT, status TEXT NOT NULL DEFAULT 'draft', note TEXT, created_at TEXT NOT NULL, created_by INTEGER REFERENCES users(id), updated_at TEXT, UNIQUE(person_id,level,province,city,district,title));
CREATE INDEX IF NOT EXISTS idx_pib_region ON pib_members(province,level,status);
 ''')
  cols={x['name'] for x in rows(c,'PRAGMA table_info(appointments)')}
  for col in ('prov_code','city_code','sebutan'):
   if col not in cols:c.execute(f'ALTER TABLE appointments ADD COLUMN {col} TEXT')
  cols={x['name'] for x in rows(c,'PRAGMA table_info(ses_assignments)')}
  for col in ('ses_prov_code','ses_city_code','review_status','review_note','submitted_by','submitted_at','replace_holder','ses_unit_code'):
   if col not in cols:c.execute(f'ALTER TABLE ses_assignments ADD COLUMN {col} TEXT')
  # V1.1: status pengajuan SK SES. Data lama: aktif/nonaktif = SK sudah diterbitkan, draft = draft.
  c.execute("UPDATE ses_assignments SET review_status=CASE WHEN status IN ('active','inactive') AND sk_no IS NOT NULL THEN 'sk_diterbitkan' ELSE 'draft' END WHERE review_status IS NULL")
  c.execute("""CREATE TRIGGER IF NOT EXISTS ses_review_default AFTER INSERT ON ses_assignments WHEN NEW.review_status IS NULL BEGIN
   UPDATE ses_assignments SET review_status=CASE WHEN NEW.status IN ('active','inactive') AND NEW.sk_no IS NOT NULL THEN 'sk_diterbitkan' ELSE 'draft' END WHERE id=NEW.id; END""")
  c.execute("INSERT OR IGNORE INTO sk_numbers(track,sk_no,ref_id,issued_at) SELECT 'SES',sk_no,id,COALESCE(approved_at,started_at,created_at) FROM ses_assignments WHERE sk_no IS NOT NULL")
  cols={x['name'] for x in rows(c,'PRAGMA table_info(appointments)')}
  for col in ('periode','end_note'):
   if col not in cols:c.execute(f'ALTER TABLE appointments ADD COLUMN {col} TEXT')
  # Status kantor (aktif/tidak) & Kesbangpol (ada/belum), keaktifan pengurus + keterangan
  cols={x['name'] for x in rows(c,'PRAGMA table_info(offices)')}
  for col,typ in (('active',"INTEGER NOT NULL DEFAULT 1"),('status_note','TEXT'),('kesbangpol',"TEXT NOT NULL DEFAULT 'belum'"),('kesbangpol_note','TEXT')):
   if col not in cols:c.execute(f'ALTER TABLE offices ADD COLUMN {col} {typ}')
  cols={x['name'] for x in rows(c,'PRAGMA table_info(appointments)')}
  for col,typ in (('activity_status',"TEXT NOT NULL DEFAULT 'aktif'"),('activity_note','TEXT'),('activity_updated_at','TEXT')):
   if col not in cols:c.execute(f'ALTER TABLE appointments ADD COLUMN {col} {typ}')
  cols={x['name'] for x in rows(c,'PRAGMA table_info(users)')}
  for col,typ in (('appointment_id','INTEGER'),('report_access','INTEGER NOT NULL DEFAULT 0')):
   if col not in cols:c.execute(f'ALTER TABLE users ADD COLUMN {col} {typ}')
  cols={x['name'] for x in rows(c,'PRAGMA table_info(activities)')}
  for col,typ in (('location','TEXT'),('purpose','TEXT'),('participants','INTEGER'),('result','TEXT'),('obstacles','TEXT'),('followup','TEXT'),('level','TEXT'),('province','TEXT'),('city','TEXT'),('district','TEXT'),
                  ('created_by','INTEGER'),('submitted_at','TEXT'),('reviewed_by','INTEGER'),('reviewed_at','TEXT'),('review_note','TEXT')):
   if col not in cols:c.execute(f'ALTER TABLE activities ADD COLUMN {col} {typ}')
  if not row(c,'SELECT id FROM users LIMIT 1'):
   sample=[('admin','superadmin','Pengelola Sistem'),('jovi','admin_wib','Jovi • Administrasi DPP'),('febri','admin_wib','Febri • Administrasi DPP'),('ihsan','ses_admin','Ihsan • Administrasi SES'),('ketum','ketum','Ketua Umum WIB'),('sekjen','sekjen','Sekretaris Jenderal'),('waketum','waketum','Wakil Ketua Umum'),('direksi','ses_director','Direksi SES Group'),('dpw_demo','dpw','Pengurus DPW • Uji Coba'),('audit','auditor','Auditor Internal')]
   passwords=[]
   for username,role,label in sample:
    passwd=secrets.token_urlsafe(14)
    c.execute('INSERT INTO users(username,password_hash,role,full_name,region) VALUES(?,?,?,?,?)',(username,hashpass(passwd),role,label,'Jawa Barat' if role=='dpw' else None))
    passwords.append((username,role,passwd))
   credentials=DATA/'AKUN_AWAL_RAHASIA.txt'
   credentials.write_text('RAHASIA - SIMPAN SECARA AMAN. Ganti kata sandi dari menu Pengaturan setelah login.\n\n'+'\n'.join(f'{username:13} | {role:14} | {passwd}' for username,role,passwd in passwords)+'\n',encoding='utf-8')
   os.chmod(credentials,0o600)
   if os.environ.get('WIB_SEED_DEMO','0')=='1':
    demos=[('Aditya Pratama','DPW','Jawa Barat','','','Ketua','active'),('Sari Wulandari','DPW','Jawa Barat','','','Sekretaris','active'),('Bima Santoso','DPD','Jawa Barat','Kabupaten Bogor','','Ketua','active'),('Ratna Permata','DPC','Jawa Barat','Kota Bandung','','Ketua','draft'),('Farhan Rahman','PAC','Jawa Barat','Kota Bandung','Coblong','Ketua','draft'),('Dewi Lestari','DPW','Jawa Tengah','','','Ketua','active'),('Rizky Mahendra','DPC','Jawa Tengah','Kota Surakarta','','Ketua','active'),('Putri Anggraini','DPW','DKI Jakarta','','','Ketua','draft'),('Nadia Salsabila','DPD','Sumatera Barat','Kabupaten Agam','','Ketua','active'),('Fajar Maulana','DPW','Banten','','','Ketua','active'),('Andi Kurniawan','DPD','Banten','Kabupaten Serang','','Bendahara','inactive'),('Yusuf Ardiansyah','DPD','Jawa Barat','Kabupaten Bekasi','','Sekretaris','active')]
    for i,(name,lev,prov,city,dist,title,status) in enumerate(demos):
     c.execute('INSERT INTO people(full_name,phone,nik_status,created_at,status) VALUES(?,?,?,?,?)',(name,None,'belum_diperiksa',now(),'active' if status=='active' else 'draft'))
     pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
     c.execute('INSERT INTO appointments(person_id,level,province,city,district,title,status,created_at,started_at) VALUES(?,?,?,?,?,?,?,?,?)',(pid,lev,prov,city,dist,title,status,now(),today() if status=='active' else None))
     aid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
     if status=='active':
      yr=2026; c.execute('INSERT INTO numbers(kind,year,sequence) VALUES(?,?,1) ON CONFLICT(kind,year) DO UPDATE SET sequence=sequence+1',('member',yr));seq=row(c,'SELECT sequence FROM numbers WHERE kind=? AND year=?',('member',yr))['sequence'];c.execute('UPDATE appointments SET member_no=?,sk_no=?,approved_at=? WHERE id=?',(f'WIB-{yr}-{seq:06d}',f'DEMO/SK-WIB/{yr}/{seq:05d}',now(),aid))
      if title=='Ketua' and i in (0,5,6,8):
       c.execute('INSERT INTO ses_assignments(person_id,wib_appointment_id,ses_role,region,status,sk_no,started_at,last_verified_at,created_at,approved_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(pid,aid,SES_ROLE[lev],city or prov,'active',f'DEMO/SK-SES/2026/{i+1:05d}',(datetime.now(TZ)-timedelta(days=(i*13+15))).date().isoformat(),(datetime.now(TZ)-timedelta(days=(i*17+3))).date().isoformat(),now(),now()))
    audit(c,None,'seed','system',0,'Data demonstrasi sintetis, bukan pengurus resmi')

initialize()

APP_INDEXES=('CREATE INDEX IF NOT EXISTS idx_app_region ON appointments(province,city,status)','CREATE INDEX IF NOT EXISTS idx_app_sk ON appointments(sk_no)')
def migrate_sk_unique(table='appointments',indexes=APP_INDEXES,old='sk_no TEXT UNIQUE',new='sk_no TEXT'):
 """Bangun ulang tabel untuk mengubah batasan UNIQUE (SQLite tidak bisa ALTER constraint). Dipakai untuk:
 nomor SK boleh sama (jabatan diganti pada bulan yang sama; nomor SK SES per kab/kota), dan V1.1: satu orang
 boleh memiliki beberapa periode pada jabatan yang sama (UNIQUE jabatan kini menyertakan periode)."""
 c=db()
 try:
  ddl=row(c,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,))['sql']
  if old not in ddl:return
  c.execute('PRAGMA foreign_keys=OFF');c.execute('BEGIN IMMEDIATE')
  try:
   c.execute(re.sub(rf'^CREATE TABLE\s+"?{table}"?',f'CREATE TABLE {table}_new',ddl,count=1).replace(old,new,1))
   c.execute(f'INSERT INTO {table}_new SELECT * FROM {table}');c.execute(f'DROP TABLE {table}');c.execute(f'ALTER TABLE {table}_new RENAME TO {table}')
   for ix in indexes:c.execute(ix)
   if c.execute('PRAGMA foreign_key_check').fetchall():raise RuntimeError('Pemeriksaan relasi gagal setelah migrasi nomor SK')
   c.execute('COMMIT')
  except:c.execute('ROLLBACK');raise
 finally:c.execute('PRAGMA foreign_keys=ON');c.close()
migrate_sk_unique()
migrate_sk_unique('ses_assignments',('CREATE INDEX IF NOT EXISTS idx_ses_sk ON ses_assignments(sk_no)',))
migrate_sk_unique('appointments',APP_INDEXES,'UNIQUE(person_id,level,province,city,district,title,started_at)','UNIQUE(person_id,level,province,city,district,title,started_at,periode)')
initialize()  # pasang ulang trigger/indeks yang ikut terhapus saat tabel dibangun ulang

@app.middleware('http')
async def headers(req:Request, call_next):
 response=await call_next(req)
 response.headers['X-Content-Type-Options']='nosniff';response.headers['X-Frame-Options']='DENY';response.headers['Referrer-Policy']='same-origin'
 response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'"
 response.headers['Cache-Control']='no-store'
 return response

def user(request:Request, write=False, allowed=None):
 tok=request.cookies.get('wib_session')
 if not tok:raise HTTPException(401,'Silakan masuk terlebih dahulu')
 c=db()
 try:
  u=row(c,'''SELECT u.id,u.username,u.role,u.full_name,u.region,u.appointment_id,u.report_access,s.csrf FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1''',(hashlib.sha256(tok.encode()).hexdigest(),int(time.time())))
  if not u:raise HTTPException(401,'Sesi tidak berlaku; silakan masuk lagi')
  if u['role']=='pengurus' and not request.url.path.startswith(PENGURUS_PATHS):raise HTTPException(403,'Akun pengurus wilayah hanya untuk laporan kegiatan')
  if allowed and u['role'] not in allowed:raise HTTPException(403,'Anda tidak memiliki kewenangan untuk tindakan ini')
  if write and not hmac.compare_digest(request.headers.get('x-csrf-token',''),u['csrf']):raise HTTPException(403,'Token keamanan tidak cocok; muat ulang halaman')
  return u
 finally:c.close()

def scope(user,prov):
 return user['role']!='dpw' or user['region']==prov

def nextno(c,kind,prefix):
 yr=datetime.now(TZ).year
 c.execute('INSERT INTO numbers(kind,year,sequence) VALUES(?,?,1) ON CONFLICT(kind,year) DO UPDATE SET sequence=sequence+1',(kind,yr))
 n=row(c,'SELECT sequence FROM numbers WHERE kind=? AND year=?',(kind,yr))['sequence']
 return prefix.format(year=yr,n=n)

class Login(BaseModel): username:str;password:str
@app.post('/api/login')
async def login(v:Login,response:Response):
 with transaction() as c:
  u=row(c,'SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1',(v.username.strip(),))
  if not u or not checkpass(v.password,u['password_hash']):raise HTTPException(401,'Pengguna atau kata sandi salah')
  tok=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(24)
  c.execute('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)',(hashlib.sha256(tok.encode()).hexdigest(),u['id'],csrf,int(time.time())+28800))
  audit(c,u['id'],'login','user',u['id'])
  response.set_cookie('wib_session',tok,httponly=True,secure=os.getenv('WIB_SECURE_COOKIE')=='1',samesite='strict',max_age=28800,path='/')
  return {'ok':True}
@app.post('/api/logout')
async def logout(request:Request,response:Response):
 u=user(request,write=True)
 with transaction() as c:c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
 response.delete_cookie('wib_session');return {'ok':True}
@app.get('/api/me')
def me(request:Request):
 u=user(request)
 if u['role']=='pengurus':
  with db() as c:u['reporter']=reporter_seat(c,u)
 return u
# Versi build: berubah setiap kode/static diperbarui. Dipakai untuk cache-busting dan agar tab yang
# masih terbuka di komputer lain tahu ada versi baru (tombol "Muat ulang").
BUILD=hashlib.sha1('|'.join(f'{f.name}:{f.stat().st_mtime_ns}' for f in sorted([*BASE.glob('*.py'),*(BASE/'static').glob('*')]) if f.is_file()).encode()).hexdigest()[:10]
@app.get('/')
def index():
 html=(BASE/'static'/'index.html').read_text(encoding='utf-8')
 for asset in ('app.css','app.js','theme.js'):html=html.replace(f'/static/{asset}"',f'/static/{asset}?v={BUILD}"')
 return HTMLResponse(html)
@app.get('/api/version')
def version():return {'build':BUILD}

@app.get('/api/dashboard')
def dashboard(request:Request):
 u=user(request)
 with db() as c:
  where='WHERE a.province=?' if u['role']=='dpw' else ''
  arg=(u['region'],) if where else ()
  appointments=rows(c,f'SELECT a.*,p.full_name FROM appointments a JOIN people p ON p.id=a.person_id {where}',arg)
  ses=rows(c,'SELECT s.*,p.full_name FROM ses_assignments s JOIN people p ON p.id=s.person_id ORDER BY s.id DESC')
  if u['role']=='dpw':ses=[x for x in ses if any(a['person_id']==x['person_id'] for a in appointments)]
  if u['role'] in ('ses_admin','ses_pic','ses_director'):
   allowed_ids={x['person_id'] for x in ses if x['status']=='active'}
   appointments=[x for x in appointments if x['person_id'] in allowed_ids]
  act=[x for x in appointments if x['status']=='active']
  bylevel={k:len([x for x in act if x['level']==k]) for k in ORGS}
  byprov={}
  for a in act:byprov[a['province']]=byprov.get(a['province'],0)+1
  ses_active=[x for x in ses if x['status']=='active']
  overdue=sum(1 for x in ses_active if age_days(x['last_verified_at'] or x['started_at'])>=90)
  offices=rows(c,'SELECT * FROM offices'+(' WHERE province=?' if u['role']=='dpw' else ''),(u['region'],) if u['role']=='dpw' else ())
  pending_docs=row(c,'SELECT COUNT(*) n FROM documents WHERE status=?',('menunggu',))['n'] if u['role'] not in ('ses_admin','ses_pic','ses_director') else row(c,"SELECT COUNT(*) n FROM documents WHERE status='menunggu' AND doc_type IN ('akta_ses_notariil','banner_ses')")['n']
  recent_wib=[{'track':'WIB','name':x['full_name'],'label':x['level'],'status':x['status'],'created_at':x['created_at']} for x in appointments]
  recent_ses=[{'track':'SES','name':x['full_name'],'label':x['ses_role'],'status':x['status'],'created_at':x['created_at']} for x in ses]
  if u['role'] in ('ses_admin','ses_pic','ses_director'):recent_wib=[]
  recent=sorted(recent_wib+recent_ses,key=lambda x:x['created_at'],reverse=True)[:7]
  return {'stats':{'total':len(appointments),'active':len(act),'ses':len(ses_active),'overdue':overdue,'pending_docs':pending_docs,'offices':len(offices)},'levels':bylevel,'provinces':dict(sorted(byprov.items(),key=lambda item:-item[1])[:7]),'statuses':{'aktif':len(act),'draft':sum(x['status']=='draft' for x in appointments),'nonaktif':sum(x['status'] not in ('active','draft') for x in appointments)},'ses_statuses':{'aktif':len(ses_active),'draft':sum(x['status']=='draft' for x in ses),'nonaktif':len(ses)-len(ses_active)-sum(x['status']=='draft' for x in ses)},'recent':recent,'demo':os.environ.get('WIB_SEED_DEMO','0')=='1'}

def age_days(date):
 if not date:return 0
 try:return max(0,(datetime.now(TZ).date()-datetime.fromisoformat(date[:10]).date()).days)
 except:return 0

@app.get('/api/people')
def people(request:Request,q:str='',level:str='',status:str='',keaktifan:str='',page:int=1,limit:int=12):
 u=user(request);page=max(1,page);limit=min(max(limit,1),100)
 where=[];args=[]
 if q:
  where.append('(p.full_name LIKE ? OR a.province LIKE ? OR a.city LIKE ? OR a.member_no LIKE ?)');args.extend(['%'+q+'%']*4)
 if level in ORGS:where.append('a.level=?');args.append(level)
 if status:where.append('a.status=?');args.append(status)
 if keaktifan in ('aktif','tidak_aktif'):where.append('a.activity_status=?');args.append(keaktifan)
 if u['role']=='dpw':where.append('a.province=?');args.append(u['region'])
 if u['role'] in ('ses_admin','ses_pic','ses_director'):
  where.append("EXISTS (SELECT 1 FROM ses_assignments sx WHERE sx.person_id=p.id AND sx.status='active')")
 filt='WHERE '+' AND '.join(where) if where else ''
 with db() as c:
  count=row(c,f'SELECT count(*) n FROM appointments a JOIN people p ON p.id=a.person_id {filt}',args)['n']
  data=rows(c,f'''SELECT a.*,p.full_name,p.phone,p.nik_status,p.status as person_status FROM appointments a JOIN people p ON p.id=a.person_id {filt} ORDER BY a.id DESC LIMIT ? OFFSET ?''',args+[limit,(page-1)*limit])
  for x in data:x['phone']=mask_phone(x['phone']) if u['role'] in ('auditor','ses_admin','ses_pic','ses_director') else x['phone']
  return {'items':data,'total':count,'page':page,'pages':math.ceil(count/limit)}

@app.get('/api/people/{person_id}')
def detail(person_id:int,request:Request):
 u=user(request)
 with db() as c:
  p=row(c,'SELECT * FROM people WHERE id=?',(person_id,))
  if not p:raise HTTPException(404,'Data orang tidak ditemukan')
  aps=rows(c,'SELECT * FROM appointments WHERE person_id=? ORDER BY id DESC',(person_id,))
  if u['role']=='dpw' and not any(a['province']==u['region'] for a in aps):raise HTTPException(403,'Di luar cakupan wilayah')
  if u['role'] in ('ses_admin','ses_pic','ses_director') and not row(c,"SELECT id FROM ses_assignments WHERE person_id=? AND (status='active' OR review_status<>'draft')",(person_id,)):
   raise HTTPException(403,'SES hanya dapat mengakses profil penerima atau pemohon SK SES')
  ses=rows(c,'SELECT * FROM ses_assignments WHERE person_id=? ORDER BY id DESC',(person_id,))
  for x in ses:x['review_label']=SES_STEPS.get(x['review_status'],x['review_status'])
  acts=rows(c,'SELECT * FROM activities WHERE person_id=? ORDER BY occurred_at DESC',(person_id,))
  # Kantor sekretariat untuk tiap jabatan (wilayah & jenjang yang sama), beserta status dan foto
  ses_role=u['role'] in ('ses_admin','ses_pic','ses_director')
  for a in aps:
   o=row(c,'SELECT * FROM offices WHERE level=? AND province=? AND city=? AND district=?',(a['level'],a['province'],a['city'] or '',a['district'] or ''))
   if o:
    ds=rows(c,"SELECT id,doc_type,status,mime,original_name,uploaded_at FROM documents WHERE target_kind='office' AND target_id=? ORDER BY id DESC",(o['id'],))
    o['kesbangpol_ada']=o['kesbangpol']=='ada' or any(d['doc_type']=='kesbangpol' and d['status']=='terverifikasi' for d in ds)
    o['photos']=[] if ses_role else [d for d in ds if d['doc_type'] in ('foto_depan','foto_dalam') and (d['mime'] or '').startswith('image/')]
   a['office']=o
  p.pop('nik_hash',None);p.pop('nik_encrypted',None)
  if u['role'] in ('ses_admin','ses_pic','ses_director','auditor'):
   p['phone']=mask_phone(p['phone']);p['address']='[terbatas]';p['nik_last4']=None;p['nik_status']='Tidak tersedia pada peran ini'
  return {'person':p,'appointments':aps,'ses':ses,'activities':acts}

class PersonCreate(BaseModel):
 full_name:str=Field(min_length=3,max_length=160)
 phone:str='';gender:str='';address:str='';nik:str='';level:str='DPW';province:str='';city:str='';district:str='';title:str='Ketua'
@app.post('/api/people')
def create_person(v:PersonCreate,request:Request):
 u=user(request,True,['superadmin','admin_wib','dpw'])
 if v.level not in ORGS or not v.province.strip():raise HTTPException(422,'Tingkat dan provinsi wajib diisi')
 if not scope(u,v.province):raise HTTPException(403,'Bukan wilayah Anda')
 if v.level in ('DPD','DPC') and not v.city.strip():raise HTTPException(422,'Kabupaten/kota wajib diisi')
 if v.level=='PAC' and not v.district.strip():raise HTTPException(422,'Kecamatan wajib diisi')
 nik=v.nik.strip();nik_h=None;nik_enc=None;last4=None;nik_stat='belum_diperiksa'
 if nik:
  if not re.fullmatch(r'\d{16}',nik):raise HTTPException(422,'NIK harus tepat 16 digit numerik')
  nik_h=nik_hash(nik);nik_enc=CRYPT.encrypt(nik.encode());last4=nik[-4:];nik_stat='format_valid_belum_dukcapil'
 with transaction() as c:
  if nik_h and row(c,'SELECT id FROM people WHERE nik_hash=?',(nik_h,)):raise HTTPException(409,'NIK sudah terdaftar; periksa data yang ada')
  c.execute('INSERT INTO people(full_name,phone,gender,address,nik_hash,nik_encrypted,nik_last4,nik_status,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',(v.full_name.strip(),v.phone.strip(),v.gender,v.address.strip(),nik_h,nik_enc,last4,nik_stat,now(),u['id']))
  pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
  c.execute('INSERT INTO appointments(person_id,level,province,city,district,title,created_at) VALUES(?,?,?,?,?,?,?)',(pid,v.level,v.province.strip(),v.city.strip(),v.district.strip(),v.title.strip(),now()))
  aid=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'create','person',pid,'pengurus draft')
 return {'ok':True,'person_id':pid,'appointment_id':aid}

class Keaktifan(BaseModel):aktif:bool;note:str=''
@app.post('/api/appointments/{id}/keaktifan')
def set_keaktifan(id:int,v:Keaktifan,request:Request):
 """Tandai pengurus aktif / tidak aktif menjalankan tugas, dengan keterangan. Tidak mengubah status SK."""
 u=user(request,True,['superadmin','admin_wib','dpw'])
 note=v.note.strip()
 if not v.aktif and len(note)<3:raise HTTPException(422,'Isi keterangan mengapa pengurus tidak aktif')
 with transaction() as c:
  a=row(c,'SELECT * FROM appointments WHERE id=?',(id,))
  if not a:raise HTTPException(404,'Jabatan tidak ditemukan')
  if not scope(u,a['province']):raise HTTPException(403,'Di luar wilayah')
  c.execute('UPDATE appointments SET activity_status=?,activity_note=?,activity_updated_at=? WHERE id=?',('aktif' if v.aktif else 'tidak_aktif',note,now(),id))
  audit(c,u['id'],'keaktifan','appointment',id,f"{'aktif' if v.aktif else 'tidak aktif'}: {note}")
 return {'ok':True}

@app.post('/api/appointments/{id}/approve')
def approve_wib(id:int,request:Request):
 u=user(request,True,['superadmin','ketum'])
 with transaction() as c:
  a=row(c,'SELECT * FROM appointments WHERE id=?',(id,))
  if not a:raise HTTPException(404,'SK WIB tidak ditemukan')
  if a['status']!='draft':raise HTTPException(409,'Hanya SK draft yang dapat disahkan')
  # Block conflicting seat; title may legitimately be held by different people across terms.
  duplicate=row(c,'''SELECT id,person_id FROM appointments WHERE level=? AND province=? AND city=? AND district=? AND title=? AND status='active' LIMIT 1''',(a['level'],a['province'],a['city'],a['district'],a['title']))
  if duplicate and duplicate['person_id']==a['person_id'] and a['periode']:
   # periode baru orang yang sama: periode sebelumnya berakhir, riwayatnya tetap tersimpan
   c.execute("UPDATE appointments SET status='inactive',ended_at=?,end_reason='periode_berakhir' WHERE id=?",(today(),duplicate['id']));duplicate=None
  if duplicate:raise HTTPException(409,'Jabatan tersebut masih diduduki pengurus aktif; lakukan pemberhentian/pergantian dahulu')
  member=row(c,"SELECT member_no FROM appointments WHERE person_id=? AND member_no IS NOT NULL ORDER BY id LIMIT 1",(a['person_id'],))
  memberno=member['member_no'] if member else nextno(c,'member','WIB-{year}-{n:06d}')
  if a['level']=='PAC':skno=nextno(c,'skwib',f'{{n:05d}}/SK-DPP/{a["level"]}/{{year}}')  # format nomor PAC belum ditetapkan DPP
  else:
   prov,reg=sk_wib.resolve_codes(a);problem=sk_wib.code_problem(a,prov,reg)
   if problem:raise HTTPException(409,problem+'. Atur di halaman Generate SK.')
   skno=sk_wib.sk_number(a,prov,reg,datetime.now(TZ).date())
   c.execute('UPDATE appointments SET prov_code=?,city_code=? WHERE id=?',(prov['kode'],reg['kode'] if reg else None,id))
  c.execute("UPDATE appointments SET status='active',member_no=?,sk_no=?,started_at=?,approved_at=?,periode=COALESCE(periode,?) WHERE id=?",(memberno,skno,today(),now(),default_periode(datetime.now(TZ).date()),id))
  c.execute("UPDATE people SET status='active' WHERE id=?",(a['person_id'],))
  if a['title'].lower().strip()=='ketua':
   reg=a['city'] if a['level'] in ('DPD','DPC') else a['district'] if a['level']=='PAC' else a['province']
   c.execute('INSERT OR IGNORE INTO ses_assignments(person_id,wib_appointment_id,ses_role,region,status,created_at) VALUES(?,?,?,?,?,?)',(a['person_id'],id,SES_ROLE[a['level']],reg,'draft',now()))
  audit(c,u['id'],'approve_wib','appointment',id,skno)
 return {'ok':True,'sk_no':skno,'member_no':memberno}

def default_periode(d):return f'{d.year}–{d.year+5}'
END_REASONS=('pemberhentian','pengunduran_diri','masa_jabatan_selesai','penggantian','mutasi','meninggal_dunia')
@app.post('/api/appointments/{id}/terminate')
def terminate_wib(id:int,request:Request,reason:str='pemberhentian',note:str=''):
 u=user(request,True,['superadmin','ketum'])
 if reason not in END_REASONS:raise HTTPException(422,'Alasan tidak sesuai')
 with transaction() as c:
  a=row(c,'SELECT * FROM appointments WHERE id=?',(id,))
  if not a or a['status']!='active':raise HTTPException(409,'Jabatan WIB tidak aktif')
  c.execute("UPDATE appointments SET status='inactive',ended_at=?,end_reason=?,end_note=? WHERE id=?",(today(),reason,note.strip()[:500] or None,id))
  if reason=='pemberhentian':
   c.execute("UPDATE ses_assignments SET status='inactive',ended_at=?,end_reason='sinkronisasi_pemberhentian_wib' WHERE person_id=? AND status IN ('active','draft')",(today(),a['person_id']))
  active=row(c,"SELECT COUNT(*) n FROM appointments WHERE person_id=? AND status='active'",(a['person_id'],))['n']
  if not active:c.execute("UPDATE people SET status='inactive' WHERE id=?",(a['person_id'],))
  audit(c,u['id'],'terminate_wib','appointment',id,reason)
 return {'ok':True}

@app.get('/api/ses')
def ses_list(request:Request,status:str=''):
 u=user(request)
 with db() as c:
  clause='WHERE s.status=?' if status else ''
  out=rows(c,f'''SELECT s.*,p.full_name,a.level,a.province,a.city FROM ses_assignments s JOIN people p ON p.id=s.person_id JOIN appointments a ON a.id=s.wib_appointment_id {clause} ORDER BY s.id DESC''',(status,) if status else ())
  if u['role']=='dpw':out=[x for x in out if x['province']==u['region']]
  for x in out:
   x['days_idle']=age_days(x['last_verified_at'] or x['started_at']) if x['status']=='active' else None
   x['needs_review']=x['days_idle'] is not None and x['days_idle']>=90
   x['review_label']=SES_STEPS.get(x['review_status'],x['review_status'])
  return {'items':out}
class SesApprove(BaseModel):note:str=''
@app.post('/api/ses/{id}/approve')
def approve_ses(id:int,request:Request,v:Optional[SesApprove]=None):
 """Pengesahan Direksi SES Group (atau pejabat berwenang). Hanya untuk pengajuan yang sudah disetujui Petugas SES;
 SK langsung terbit dengan nomor unik yang tidak dapat dipakai ulang."""
 u=user(request,True,['superadmin','ses_director'])
 with transaction() as c:
  s=row(c,'SELECT * FROM ses_assignments WHERE id=?',(id,))
  if not s:raise HTTPException(404,'Pengajuan SK SES tidak ditemukan')
  if s['review_status']!='menunggu_pengesahan':raise HTTPException(409,f"Pengajuan berstatus {SES_STEPS.get(s['review_status'],s['review_status'])}. Pengesahan hanya untuk pengajuan yang sudah disetujui Petugas SES.")
  a=row(c,'SELECT * FROM appointments WHERE id=?',(s['wib_appointment_id'],))
  if a['status']!='active':raise HTTPException(409,'SK WIB terkait belum aktif')
  when=datetime.now(TZ).date()
  ses_log(c,u,id,'disahkan',s['review_status'],'disetujui',(v.note if v else '') or 'Disahkan')
  if s['ses_role'] in sk_ses.ROLES:
   info=ses_info(c,s)
   if info['problem']:raise HTTPException(409,info['problem'])
   holder=ses_holders(c).get(info['key'])
   if holder and holder['person_id']!=s['person_id']:
    if s['replace_holder']!='1':raise HTTPException(409,f"{info['wilayah']} masih memiliki {s['ses_role']} aktif ({holder['full_name']}) dan pengajuan ini tidak ditandai sebagai penggantian.")
    c.execute("UPDATE ses_assignments SET status='inactive',ended_at=?,end_reason='penggantian' WHERE id=?",(when.isoformat(),holder['id']))
    audit(c,u['id'],'terminate_ses','ses_assignment',holder['id'],f"penggantian {s['ses_role']}")
   sk=issue_ses_sk(c,id,s['ses_role'],info['prov'],info['reg'],info['unit'],info['wilayah'],when)
  else:
   sk=nextno(c,'skses','{n:05d}/SK-SES/{year}')
   c.execute("UPDATE ses_assignments SET status='active',sk_no=?,started_at=?,approved_at=? WHERE id=?",(sk,today(),now(),id))
   register_ses_number(c,sk,id)
  c.execute("UPDATE ses_assignments SET review_status='sk_diterbitkan' WHERE id=?",(id,))
  ses_log(c,u,id,'sk_diterbitkan','disetujui','sk_diterbitkan',f'SK {sk} diterbitkan otomatis oleh sistem')
  audit(c,u['id'],'approve_ses','ses_assignment',id,sk)
 return {'ok':True,'sk_no':sk}
@app.post('/api/ses/{id}/terminate')
def terminate_ses(id:int,request:Request,reason:str='evaluasi_kinerja'):
 u=user(request,True,['superadmin','ses_director'])
 with transaction() as c:
  s=row(c,'SELECT * FROM ses_assignments WHERE id=?',(id,))
  if not s or s['status']!='active':raise HTTPException(409,'Penugasan SES tidak aktif')
  c.execute('UPDATE ses_assignments SET status=?,ended_at=?,end_reason=? WHERE id=?',('inactive',today(),reason,id))
  audit(c,u['id'],'terminate_ses','ses_assignment',id,reason)
 return {'ok':True}

class Activity(BaseModel):track:str;person_id:int;appointment_id:Optional[int]=None;category:str;title:str;description:str='';occurred_at:str=''
@app.get('/api/activities')
def activity_list(request:Request,track:str=''):
 u=user(request)
 with db() as c:
  data=rows(c,'''SELECT t.*,p.full_name FROM activities t JOIN people p ON p.id=t.person_id ORDER BY t.id DESC LIMIT 250''')
  if track:data=[x for x in data if x['track']==track]
  if u['role'] in ('ses_admin','ses_pic','ses_director'):
   allowed={x['person_id'] for x in rows(c,"SELECT person_id FROM ses_assignments WHERE status='active'")}
   data=[x for x in data if x['person_id'] in allowed and x['track']=='SES']
  if u['role']=='dpw':
   ids={x['person_id'] for x in rows(c,'SELECT person_id FROM appointments WHERE province=?',(u['region'],))};data=[x for x in data if x['person_id'] in ids]
  return {'items':data}
@app.post('/api/activities')
def add_activity(v:Activity,request:Request):
 u=user(request,True,['superadmin','admin_wib','dpw','ses_admin','ses_pic'])
 if v.track not in ('WIB','SES'):raise HTTPException(422,'Bidang harus WIB/SES')
 if v.track=='SES' and u['role'] not in ('superadmin','ses_admin','ses_pic'):raise HTTPException(403,'Kegiatan SES melalui PIC SES')
 with transaction() as c:
  p=row(c,'SELECT id FROM people WHERE id=?',(v.person_id,))
  if not p:raise HTTPException(404,'Pengurus tidak ditemukan')
  if u['role']=='dpw' and not row(c,'SELECT id FROM appointments WHERE person_id=? AND province=?',(v.person_id,u['region'])):raise HTTPException(403,'Di luar wilayah')
  c.execute('INSERT INTO activities(track,person_id,appointment_id,category,title,description,occurred_at,created_at) VALUES(?,?,?,?,?,?,?,?)',(v.track,v.person_id,v.appointment_id,v.category,v.title,v.description,v.occurred_at or today(),now()))
  ident=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'create','activity',ident,v.track)
 return {'ok':True,'id':ident}
@app.post('/api/activities/{id}/verify')
def verify_activity(id:int,request:Request):
 u=user(request,True,['superadmin','ketum','sekjen','waketum','ses_admin','ses_director'])
 with transaction() as c:
  a=row(c,'SELECT * FROM activities WHERE id=?',(id,))
  if not a:raise HTTPException(404,'Kegiatan tidak ditemukan')
  if a['track']=='SES' and u['role'] not in ('superadmin','ses_admin','ses_director'):raise HTTPException(403,'Verifikasi SES harus oleh SES Group')
  if a['track']=='WIB' and u['role']=='ses_admin':raise HTTPException(403,'Tidak berwenang verifikasi WIB')
  c.execute("UPDATE activities SET status='terverifikasi',verified_at=?,verified_by=? WHERE id=?",(now(),u['id'],id))
  if a['track']=='SES':c.execute("UPDATE ses_assignments SET last_verified_at=? WHERE person_id=? AND status='active'",(a['occurred_at'],a['person_id']))
  audit(c,u['id'],'verify','activity',id)
 return {'ok':True}

class Opportunity(BaseModel):person_id:int;ses_assignment_id:Optional[int]=None;region:str;category:str;title:str;description:str='';organization:str='';estimated_value:Optional[float]=None
@app.get('/api/opportunities')
def opportunities(request:Request):
 u=user(request)
 with db() as c:
  data=rows(c,'SELECT o.*,p.full_name FROM opportunities o JOIN people p ON p.id=o.person_id ORDER BY o.id DESC LIMIT 200')
  if u['role']=='dpw':data=[x for x in data if u['region'] in x['region']]
  return {'items':data}
@app.post('/api/opportunities')
def add_opportunity(v:Opportunity,request:Request):
 u=user(request,True,['superadmin','ses_admin','ses_pic','ses_director','dpw'])
 with transaction() as c:
  if not row(c,'SELECT id FROM people WHERE id=?',(v.person_id,)):raise HTTPException(404,'Pengurus tidak ditemukan')
  if u['role']=='dpw' and u['region'] not in v.region:raise HTTPException(403,'Di luar wilayah')
  c.execute('INSERT INTO opportunities(person_id,ses_assignment_id,region,category,title,description,organization,estimated_value,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(v.person_id,v.ses_assignment_id,v.region,v.category,v.title,v.description,v.organization,v.estimated_value,now(),now()))
  ident=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'create','opportunity',ident)
 return {'ok':True,'id':ident}

class Office(BaseModel):level:str;province:str;city:str='';district:str='';address:str;active:bool=True;status_note:str='';kesbangpol:str='belum';kesbangpol_note:str=''
class OfficeStatus(BaseModel):active:bool;status_note:str='';kesbangpol:str;kesbangpol_note:str=''
def office_status_check(v):
 if v.kesbangpol not in ('ada','belum'):raise HTTPException(422,'Status Kesbangpol harus "ada" atau "belum"')
 if not v.active and len(v.status_note.strip())<3:raise HTTPException(422,'Isi keterangan mengapa kantor tidak aktif')
@app.get('/api/offices')
def offices(request:Request):
 u=user(request)
 with db() as c:
  data=rows(c,'SELECT * FROM offices ORDER BY updated_at DESC')
  if u['role']=='dpw':data=[x for x in data if x['province']==u['region']]
  for x in data:
   ds=rows(c,'SELECT doc_type,status FROM documents WHERE target_kind=? AND target_id=?',('office',x['id']))
   x['docs']={k:any(v['doc_type']==k and v['status']=='terverifikasi' for v in ds) for k in ['kesbangpol','akta_ses_notariil','foto_depan','foto_dalam','banner_ses']}
   x['compliance']=sum(x['docs'].values())
   x['kesbangpol_ada']=x['kesbangpol']=='ada' or x['docs']['kesbangpol']
  return {'items':data}
@app.post('/api/offices')
def save_office(v:Office,request:Request):
 u=user(request,True,['superadmin','admin_wib','dpw'])
 if v.level not in ORGS or not v.province.strip() or not v.address.strip():raise HTTPException(422,'Tingkat, provinsi dan alamat wajib diisi')
 if not scope(u,v.province):raise HTTPException(403,'Di luar wilayah')
 office_status_check(v)
 with transaction() as c:
  c.execute('''INSERT INTO offices(level,province,city,district,address,updated_at,active,status_note,kesbangpol,kesbangpol_note) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(level,province,city,district) DO UPDATE SET address=excluded.address,updated_at=excluded.updated_at,active=excluded.active,status_note=excluded.status_note,kesbangpol=excluded.kesbangpol,kesbangpol_note=excluded.kesbangpol_note''',(v.level,v.province,v.city,v.district,v.address,now(),int(v.active),v.status_note.strip(),v.kesbangpol,v.kesbangpol_note.strip()))
  ident=row(c,'SELECT id FROM offices WHERE level=? AND province=? AND city=? AND district=?',(v.level,v.province,v.city,v.district))['id']
  audit(c,u['id'],'upsert','office',ident)
 return {'ok':True,'id':ident}
@app.post('/api/offices/{id}/status')
def office_status(id:int,v:OfficeStatus,request:Request):
 """Ubah status kantor (aktif/tidak aktif + keterangan) dan status Kesbangpol (ada/belum + keterangan)."""
 u=user(request,True,['superadmin','admin_wib','dpw'])
 office_status_check(v)
 with transaction() as c:
  o=row(c,'SELECT * FROM offices WHERE id=?',(id,))
  if not o:raise HTTPException(404,'Kantor tidak ditemukan')
  if not scope(u,o['province']):raise HTTPException(403,'Di luar wilayah')
  c.execute('UPDATE offices SET active=?,status_note=?,kesbangpol=?,kesbangpol_note=?,updated_at=? WHERE id=?',(int(v.active),v.status_note.strip(),v.kesbangpol,v.kesbangpol_note.strip(),now(),id))
  audit(c,u['id'],'office_status','office',id,f"{'aktif' if v.active else 'tidak aktif'}; kesbangpol={v.kesbangpol}; {v.status_note.strip()}")
 return {'ok':True}

# ===================== Data Pengurus PIB (Partai Indonesia Bergerak) =====================
class PibMember(BaseModel):
 person_id:Optional[int]=None;full_name:str='';phone:str=''
 level:str;province:str;city:str='';district:str='';title:str
 kta_no:str='';status:str='draft';note:str=''
class PibUpdate(BaseModel):
 level:str;province:str;city:str='';district:str='';title:str;kta_no:str='';status:str='draft';note:str=''
class PibImport(BaseModel):level:str='';province:str='';title:str=''
def pib_check(v):
 if v.level not in ORGS:raise HTTPException(422,'Jenjang harus DPW, DPD, DPC, atau PAC')
 if not v.province.strip():raise HTTPException(422,'Provinsi wajib diisi')
 if v.level in ('DPD','DPC','PAC') and not v.city.strip():raise HTTPException(422,'Kabupaten/kota wajib diisi untuk jenjang '+v.level)
 if v.level=='PAC' and not v.district.strip():raise HTTPException(422,'Kecamatan wajib diisi untuk PAC')
 if not v.title.strip():raise HTTPException(422,'Jabatan wajib diisi')
 if v.status not in ('draft','active','inactive'):raise HTTPException(422,'Status tidak dikenal')
 if v.status=='inactive' and not v.note.strip():raise HTTPException(422,'Keterangan wajib diisi bila status tidak aktif')
def pib_docs(c,ids):
 out={i:{} for i in ids}
 if not ids:return out
 for d in rows(c,f"SELECT id,target_id,doc_type,status,original_name,uploaded_at,mime FROM documents WHERE target_kind='pib' AND target_id IN ({','.join('?'*len(ids))}) ORDER BY id DESC",list(ids)):
  cur=out[d['target_id']].get(d['doc_type'])
  if not cur or (cur['status']!='terverifikasi' and d['status']=='terverifikasi'):out[d['target_id']][d['doc_type']]=d
 return out
def pib_summary(x,docs):
 x['docs']={k:(docs.get(k) or {}).get('status') for k in PIB_DOCS}
 x['docs_uploaded']=sum(1 for k in PIB_REQUIRED if docs.get(k))
 x['docs_verified']=sum(1 for k in PIB_REQUIRED if (docs.get(k) or {}).get('status')=='terverifikasi')
 x['docs_required']=len(PIB_REQUIRED)
 x['lengkap']=x['docs_verified']==len(PIB_REQUIRED)
 return x
def pib_where(u,q='',level='',province='',status='',kelengkapan=''):
 where=[];args=[]
 if q:where.append('(p.full_name LIKE ? OR m.province LIKE ? OR m.city LIKE ? OR m.kta_no LIKE ? OR m.title LIKE ?)');args.extend(['%'+q+'%']*5)
 if level in ORGS:where.append('m.level=?');args.append(level)
 if province:where.append('m.province=?');args.append(province)
 if status in ('draft','active','inactive'):where.append('m.status=?');args.append(status)
 if u['role']=='dpw':where.append('m.province=?');args.append(u['region'])
 req=f"(SELECT count(DISTINCT d.doc_type) FROM documents d WHERE d.target_kind='pib' AND d.target_id=m.id AND d.status='terverifikasi' AND d.doc_type IN ({','.join('?'*len(PIB_REQUIRED))}))"
 if kelengkapan=='lengkap':where.append(req+'=?');args.extend(PIB_REQUIRED+[len(PIB_REQUIRED)])
 if kelengkapan=='belum':where.append(req+'<?');args.extend(PIB_REQUIRED+[len(PIB_REQUIRED)])
 return ('WHERE '+' AND '.join(where) if where else ''),args
@app.get('/api/pib')
def pib_list(request:Request,q:str='',level:str='',province:str='',status:str='',kelengkapan:str='',page:int=1,limit:int=15):
 u=user(request,allowed=PIB_VIEWERS);page=max(1,page);limit=min(max(limit,1),100)
 filt,args=pib_where(u,q,level,province,status,kelengkapan)
 with db() as c:
  total=row(c,f'SELECT count(*) n FROM pib_members m JOIN people p ON p.id=m.person_id {filt}',args)['n']
  data=rows(c,f"""SELECT m.*,p.full_name,p.phone,p.nik_status,a.title as wib_title,a.level as wib_level,a.status as wib_status FROM pib_members m JOIN people p ON p.id=m.person_id LEFT JOIN appointments a ON a.id=m.wib_appointment_id {filt} ORDER BY CASE m.level WHEN 'DPW' THEN 1 WHEN 'DPD' THEN 2 WHEN 'DPC' THEN 3 ELSE 4 END,m.province,m.city,m.district,m.id LIMIT ? OFFSET ?""",args+[limit,(page-1)*limit])
  docs=pib_docs(c,[x['id'] for x in data])
  for x in data:
   pib_summary(x,docs[x['id']])
   if u['role']=='auditor':x['phone']=mask_phone(x['phone'])
  s_where='WHERE m.province=?' if u['role']=='dpw' else '';s_args=[u['region']] if u['role']=='dpw' else []
  stats=row(c,f"SELECT count(*) total,sum(m.status='active') aktif,sum(m.status='draft') proses,sum(m.status='inactive') nonaktif FROM pib_members m {s_where}",s_args)
  wib_total=row(c,"SELECT count(*) n FROM appointments WHERE status='active'"+(' AND province=?' if u['role']=='dpw' else ''),s_args)['n']
 return {'items':data,'total':total,'page':page,'pages':math.ceil(total/limit),'stats':{k:stats[k] or 0 for k in ('total','aktif','proses','nonaktif')},'wib_active':wib_total,'required':PIB_REQUIRED,'doc_types':PIB_DOCS}
@app.get('/api/pib/{id}')
def pib_detail(id:int,request:Request):
 u=user(request,allowed=PIB_VIEWERS)
 with db() as c:
  x=row(c,'SELECT m.*,p.full_name,p.phone,p.gender,p.nik_status,p.nik_last4 FROM pib_members m JOIN people p ON p.id=m.person_id WHERE m.id=?',(id,))
  if not x:raise HTTPException(404,'Data pengurus PIB tidak ditemukan')
  if not scope(u,x['province']):raise HTTPException(403,'Di luar cakupan wilayah')
  if u['role']=='auditor':x['phone']=mask_phone(x['phone'])
  pib_summary(x,pib_docs(c,[id])[id])
  x['documents']=rows(c,"SELECT d.id,d.doc_type,d.status,d.original_name,d.mime,d.uploaded_at,d.verified_at,us.full_name uploader FROM documents d LEFT JOIN users us ON us.id=d.uploaded_by WHERE d.target_kind='pib' AND d.target_id=? ORDER BY d.id DESC",(id,))
  x['wib']=rows(c,'SELECT id,level,province,city,district,title,status,member_no,sk_no FROM appointments WHERE person_id=? ORDER BY id DESC',(x['person_id'],))
  x['required']=PIB_REQUIRED;x['doc_types']=PIB_DOCS
 return x
@app.post('/api/pib')
def pib_create(v:PibMember,request:Request):
 u=user(request,True,PIB_EDITORS);pib_check(v)
 if not scope(u,v.province):raise HTTPException(403,'Di luar cakupan wilayah')
 with transaction() as c:
  if v.person_id:
   if not row(c,'SELECT id FROM people WHERE id=?',(v.person_id,)):raise HTTPException(404,'Orang tidak ditemukan')
   pid=v.person_id
  else:
   if len(v.full_name.strip())<3:raise HTTPException(422,'Nama lengkap wajib diisi')
   c.execute("INSERT INTO people(full_name,phone,created_at,created_by,status) VALUES(?,?,?,?, 'draft')",(v.full_name.strip(),v.phone.strip() or None,now(),u['id']))
   pid=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'create','person',pid,'dari data PIB')
  if row(c,'SELECT id FROM pib_members WHERE person_id=? AND level=? AND province=? AND city=? AND district=? AND title=?',(pid,v.level,v.province.strip(),v.city.strip(),v.district.strip(),v.title.strip())):
   raise HTTPException(409,'Orang ini sudah tercatat dengan jabatan PIB yang sama')
  c.execute('INSERT INTO pib_members(person_id,level,province,city,district,title,kta_no,status,note,created_at,created_by,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(pid,v.level,v.province.strip(),v.city.strip(),v.district.strip(),v.title.strip(),v.kta_no.strip() or None,v.status,v.note.strip() or None,now(),u['id'],now()))
  ident=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'create','pib_member',ident,f'{v.title} {v.level} {v.province}')
 return {'ok':True,'id':ident}
@app.put('/api/pib/{id}')
def pib_update(id:int,v:PibUpdate,request:Request):
 u=user(request,True,PIB_EDITORS);pib_check(v)
 with transaction() as c:
  x=row(c,'SELECT * FROM pib_members WHERE id=?',(id,))
  if not x:raise HTTPException(404,'Data pengurus PIB tidak ditemukan')
  if not scope(u,x['province']) or not scope(u,v.province):raise HTTPException(403,'Di luar cakupan wilayah')
  try:c.execute('UPDATE pib_members SET level=?,province=?,city=?,district=?,title=?,kta_no=?,status=?,note=?,updated_at=? WHERE id=?',(v.level,v.province.strip(),v.city.strip(),v.district.strip(),v.title.strip(),v.kta_no.strip() or None,v.status,v.note.strip() or None,now(),id))
  except sqlite3.IntegrityError:raise HTTPException(409,'Orang ini sudah tercatat dengan jabatan PIB yang sama')
  audit(c,u['id'],'update','pib_member',id,f'{v.title} {v.level} {v.province}; status={v.status}')
 return {'ok':True}
@app.delete('/api/pib/{id}')
def pib_delete(id:int,request:Request):
 u=user(request,True,['superadmin','admin_wib'])
 with transaction() as c:
  x=row(c,'SELECT * FROM pib_members WHERE id=?',(id,))
  if not x:raise HTTPException(404,'Data pengurus PIB tidak ditemukan')
  n=row(c,"SELECT count(*) n FROM documents WHERE target_kind='pib' AND target_id=?",(id,))['n']
  if n:raise HTTPException(409,f'Masih ada {n} dokumen PIB. Ubah status menjadi tidak aktif saja.')
  c.execute('DELETE FROM pib_members WHERE id=?',(id,));audit(c,u['id'],'delete','pib_member',id,f"{x['title']} {x['level']} {x['province']}")
 return {'ok':True}
@app.post('/api/pib/import-wib')
def pib_import(v:PibImport,request:Request):
 """Salin pengurus WIB aktif menjadi data pengurus PIB (status proses). Tidak menduplikasi yang sudah ada."""
 u=user(request,True,PIB_EDITORS)
 where=["a.status='active'"];args=[]
 if v.level in ORGS:where.append('a.level=?');args.append(v.level)
 if v.province:where.append('a.province=?');args.append(v.province)
 titles=[t.strip().lower() for t in v.title.split(',') if t.strip()]
 if titles:where.append(f"lower(trim(a.title)) IN ({','.join('?'*len(titles))})");args.extend(titles)
 if u['role']=='dpw':where.append('a.province=?');args.append(u['region'])
 made=skip=0
 with transaction() as c:
  for a in rows(c,f"SELECT a.* FROM appointments a WHERE {' AND '.join(where)}",args):
   if row(c,'SELECT id FROM pib_members WHERE wib_appointment_id=? OR (person_id=? AND level=? AND province=? AND city=? AND district=? AND title=?)',(a['id'],a['person_id'],a['level'],a['province'],a['city'] or '',a['district'] or '',a['title'])):skip+=1;continue
   c.execute("INSERT INTO pib_members(person_id,wib_appointment_id,level,province,city,district,title,status,created_at,created_by,updated_at) VALUES(?,?,?,?,?,?,?,'draft',?,?,?)",(a['person_id'],a['id'],a['level'],a['province'],a['city'] or '',a['district'] or '',a['title'],now(),u['id'],now()));made+=1
  audit(c,u['id'],'import_wib','pib_member',None,f'dibuat={made}; sudah ada={skip}; {v.level} {v.province} {v.title}')
 return {'ok':True,'created':made,'skipped':skip}
@app.get('/api/export-pib.csv')
def export_pib(request:Request,level:str='',province:str='',status:str='',kelengkapan:str=''):
 u=user(request,allowed=PIB_VIEWERS)
 filt,args=pib_where(u,'',level,province,status,kelengkapan)
 LBL={'ktp':'KTP','pas_foto':'Pas foto','kta_pib':'KTA PIB','pakta_integritas':'Pakta integritas','surat_kesediaan':'Surat kesediaan','surat_bukan_parpol_lain':'Surat tidak anggota parpol lain','daftar_riwayat_hidup':'Daftar riwayat hidup','surat_domisili':'Surat domisili'}
 out=io.StringIO();w=csv.writer(out);w.writerow(['Nama','Telepon','Jenjang','Provinsi','Kabupaten/Kota','Kecamatan','Jabatan PIB','Nomor KTA PIB','Status','Keterangan','Jabatan WIB']+[LBL[k] for k in PIB_REQUIRED+['surat_domisili']]+['Kelengkapan wajib'])
 with db() as c:
  data=rows(c,f"SELECT m.*,p.full_name,p.phone,a.title wib_title,a.level wib_level FROM pib_members m JOIN people p ON p.id=m.person_id LEFT JOIN appointments a ON a.id=m.wib_appointment_id {filt} ORDER BY m.province,m.level,m.city",args)
  docs=pib_docs(c,[x['id'] for x in data])
  for x in data:
   pib_summary(x,docs[x['id']]);st={'draft':'Proses','active':'Aktif','inactive':'Tidak aktif'}[x['status']]
   values=[x['full_name'],mask_phone(x['phone']) if u['role']=='auditor' else x['phone'],x['level'],x['province'],x['city'],x['district'],x['title'],x['kta_no'],st,x['note'] or '',f"{x['wib_title']} {x['wib_level']}" if x['wib_title'] else '']+[{'terverifikasi':'Terverifikasi','menunggu':'Menunggu verifikasi'}.get(x['docs'][k],'Belum ada') for k in PIB_REQUIRED+['surat_domisili']]+[f"{x['docs_verified']}/{x['docs_required']}"]
   w.writerow(["'"+str(y) if y and str(y)[0] in '=+-@' else y for y in values])
 return Response('﻿'+out.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="rekap_pengurus_pib.csv"'})

@app.get('/api/documents')
def doc_list(request:Request,target_kind:str='',target_id:int=0):
 u=user(request)
 with db() as c:
  data=rows(c,'''SELECT d.*,u.full_name as uploader FROM documents d LEFT JOIN users u ON u.id=d.uploaded_by ORDER BY d.id DESC LIMIT 250''')
  if target_kind:data=[x for x in data if x['target_kind']==target_kind]
  if target_id:data=[x for x in data if x['target_id']==target_id]
  if u['role']=='dpw':
   officeids={x['id'] for x in rows(c,'SELECT id FROM offices WHERE province=?',(u['region'],))};personids={x['person_id'] for x in rows(c,'SELECT person_id FROM appointments WHERE province=?',(u['region'],))}
   pibids={x['id'] for x in rows(c,'SELECT id FROM pib_members WHERE province=?',(u['region'],))}
   data=[x for x in data if (x['target_kind']=='office' and x['target_id'] in officeids) or (x['target_kind']=='person' and x['target_id'] in personids) or (x['target_kind']=='pib' and x['target_id'] in pibids)]
  if u['role'] in ('ses_admin','ses_pic','ses_director'):
   review={x['person_id'] for x in rows(c,"SELECT person_id FROM ses_assignments WHERE review_status<>'draft'")}
   data=[x for x in data if (x['target_kind']=='office' and x['doc_type'] in ('akta_ses_notariil','banner_ses','lainnya')) or (x['target_kind']=='person' and x['target_id'] in review)]
  if u['role']=='auditor':
   data=[x for x in data if x['doc_type'] not in ('ktp','akta_wib','ahu_wib','ad_art','npwp_wib')]
  return {'items':[{k:v for k,v in x.items() if k!='stored_name'} for x in data]}
@app.post('/api/documents/upload')
async def upload_document(request:Request,file:UploadFile=File(...),target_kind:str=Form(...),target_id:int=Form(...),doc_type:str=Form(...)):
 u=user(request,True,['superadmin','admin_wib','dpw','ses_admin','ses_pic','ketum'])
 allowed_types={'office':OFFICE_DOCS,'person':PERSON_DOCS,'appointment':APPOINTMENT_DOCS,'pib':PIB_DOCS}.get(target_kind)
 if not allowed_types or doc_type not in allowed_types:
  if target_kind=='person' and doc_type=='akta_ses_notariil':raise HTTPException(422,'Salinan akta SES notarial diunggah pada modul Kantor & Legalitas (legalitas kantor/cabang SES Group), bukan profil pengurus')
  raise HTTPException(422,'Jenis dokumen tidak dikenal untuk tujuan ini')
 if target_kind=='appointment' and u['role'] not in ('superadmin','admin_wib','ketum'):raise HTTPException(403,'Dokumen keputusan diunggah oleh DPP')
 if target_kind=='pib' and u['role'] not in PIB_EDITORS:raise HTTPException(403,'Dokumen PIB diunggah oleh DPP atau DPW')
 if u['role'] in ('ses_admin','ses_pic') and (target_kind!='office' or doc_type not in ('akta_ses_notariil','banner_ses','lainnya')):raise HTTPException(403,'Admin SES hanya mengunggah dokumen kantor SES')
 with db() as c:
  obj=row(c,{'office':'SELECT * FROM offices WHERE id=?','person':'SELECT * FROM people WHERE id=?','appointment':'SELECT * FROM appointments WHERE id=?','pib':'SELECT * FROM pib_members WHERE id=?'}[target_kind],(target_id,))
  if not obj:raise HTTPException(404,'Tujuan dokumen tidak ditemukan')
  if u['role']=='dpw':
   good=obj['province']==u['region'] if target_kind in ('office','pib') else bool(row(c,'SELECT id FROM appointments WHERE person_id=? AND province=?',(target_id,u['region'])))
   if not good:raise HTTPException(403,'Di luar wilayah')
 ext=Path(file.filename or '').suffix.lower();allowed={'.pdf':'application/pdf','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp'}
 if ext not in allowed:raise HTTPException(422,'Unggah PDF, JPG, PNG, atau WEBP')
 content=await file.read(5*1024*1024+1)
 if len(content)>5*1024*1024:raise HTTPException(413,'Ukuran maksimum 5 MB')
 if ext=='.pdf' and not content.startswith(b'%PDF-'):raise HTTPException(422,'Isi berkas bukan PDF')
 if ext in ('.jpg','.jpeg') and not content.startswith(b'\xff\xd8'):raise HTTPException(422,'Isi berkas bukan JPEG')
 if ext=='.png' and not content.startswith(b'\x89PNG') :raise HTTPException(422,'Isi berkas bukan PNG')
 if ext=='.webp' and content[:4]!=b'RIFF':raise HTTPException(422,'Isi berkas bukan WEBP')
 filename=secrets.token_hex(18)+ext;(PRIVATE/filename).write_bytes(content)
 with transaction() as c:
  c.execute('INSERT INTO documents(target_kind,target_id,doc_type,original_name,stored_name,mime,size,uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?)',(target_kind,target_id,doc_type,Path(file.filename).name[:180],filename,allowed[ext],len(content),u['id'],now()))
  ident=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'upload','document',ident,doc_type)
 return {'ok':True,'id':ident}
@app.post('/api/documents/{id}/verify')
def doc_verify(id:int,request:Request):
 u=user(request,True,['superadmin','admin_wib','ketum','sekjen','ses_admin','ses_director'])
 with transaction() as c:
  d=row(c,'SELECT * FROM documents WHERE id=?',(id,))
  if not d:raise HTTPException(404,'Dokumen tidak ditemukan')
  if d['doc_type'] in ('akta_ses_notariil','banner_ses') and u['role'] not in ('superadmin','ses_admin','ses_director'):raise HTTPException(403,'Dokumen SES hanya diverifikasi tim SES')
  if d['doc_type'] not in ('akta_ses_notariil','banner_ses') and u['role']=='ses_admin':raise HTTPException(403,'Dokumen WIB harus diverifikasi DPP WIB')
  c.execute("UPDATE documents SET status='terverifikasi',verified_by=?,verified_at=? WHERE id=?",(u['id'],now(),id))
  audit(c,u['id'],'verify','document',id,d['doc_type'])
 return {'ok':True}
@app.get('/api/documents/{id}/download')
def doc_download(id:int,request:Request):
 u=user(request)
 with db() as c:
  d=row(c,'SELECT * FROM documents WHERE id=?',(id,))
  if not d:raise HTTPException(404,'Dokumen tidak ditemukan')
  if u['role']=='dpw':
   if d['target_kind']=='office':o=row(c,'SELECT province FROM offices WHERE id=?',(d['target_id'],));good=o and o['province']==u['region']
   elif d['target_kind']=='pib':o=row(c,'SELECT province FROM pib_members WHERE id=?',(d['target_id'],));good=o and o['province']==u['region']
   else:good=row(c,'SELECT id FROM appointments WHERE person_id=? AND province=?',(d['target_id'],u['region']))
   if not good:raise HTTPException(403,'Di luar wilayah')
  if u['role'] in ('ses_admin','ses_pic','ses_director') and not (d['target_kind']=='office' and d['doc_type'] in ('akta_ses_notariil','banner_ses','lainnya')) and not (d['target_kind']=='person' and row(c,"SELECT id FROM ses_assignments WHERE person_id=? AND review_status<>'draft'",(d['target_id'],))):
   raise HTTPException(403,'Dokumen berada di luar kewenangan SES')
  if u['role']=='auditor' and d['doc_type'] in ('ktp','akta_wib','ahu_wib','ad_art','npwp_wib'):
   raise HTTPException(403,'Dokumen internal WIB tidak tersedia pada portal SES')
  path=PRIVATE/d['stored_name']
  if not path.exists():raise HTTPException(404,'Berkas tidak tersedia')
  audit_extra=None
  return FileResponse(path,media_type=d['mime'],filename=d['original_name'])

@app.get('/api/evaluations')
def eval_list(request:Request,track:str='WIB'):
 u=user(request)
 with db() as c:
  past=rows(c,'SELECT e.*,u.full_name as evaluator_name FROM evaluations e LEFT JOIN users u ON u.id=e.evaluator WHERE e.track=? ORDER BY e.id DESC LIMIT 100',(track,))
  if track=='SES':
   entities=rows(c,'SELECT s.id,s.status,p.full_name as name,s.ses_role as title,s.region,s.last_verified_at,s.started_at FROM ses_assignments s JOIN people p ON p.id=s.person_id')
   for x in entities:
    x['days_idle']=age_days(x['last_verified_at'] or x['started_at']);x['flagged']=x['status']=='active' and x['days_idle']>=90
  else:
   entities=rows(c,"SELECT a.id,a.status,p.full_name as name,a.title,a.level,a.province as region,a.city,a.district,a.started_at FROM appointments a JOIN people p ON p.id=a.person_id")
   acc=accepted_reports(c);cq=current_quarter();pq=last_quarters(2)[0]
   for x in entities:
    k=(x['level'],x['region'],x['city'] or '',x['district'] or '')
    x['reports_q']=acc.get(k+(cq,),0);x['reports_prev']=acc.get(k+(pq,),0);x['quarter']=cq
    x['days_idle']=age_days(x['started_at'])
    # indikator: jabatan aktif >= 90 hari tanpa laporan kegiatan diterima pada triwulan ini & sebelumnya
    x['flagged']=x['status']=='active' and x['days_idle']>=90 and not (x['reports_q'] or x['reports_prev'])
  if u['role']=='dpw':entities=[x for x in entities if x['region']==u['region']]
  return {'items':entities,'history':past}
class Evaluation(BaseModel):track:str;entity_id:int;period:str;score:int=Field(ge=0,le=100);notes:str=''
@app.post('/api/evaluations')
def add_eval(v:Evaluation,request:Request):
 u=user(request,True,['superadmin','ketum','sekjen','waketum','ses_admin','ses_director'])
 if v.track not in ('WIB','SES') or not re.fullmatch(r'\d{4}-Q[1-4]',v.period):raise HTTPException(422,'Trek atau periode tidak valid')
 if v.track=='SES' and u['role'] not in ('superadmin','ses_admin','ses_director'):raise HTTPException(403,'Evaluator SES tidak sesuai')
 if v.track=='WIB' and u['role']=='ses_admin':raise HTTPException(403,'Evaluator WIB tidak sesuai')
 with transaction() as c:
  tbl='ses_assignments' if v.track=='SES' else 'appointments'
  if not row(c,f'SELECT id FROM {tbl} WHERE id=?',(v.entity_id,)):raise HTTPException(404,'Jabatan tidak ditemukan')
  result='Baik' if v.score>=80 else 'Pembinaan' if v.score>=60 else 'Perlu evaluasi'
  c.execute('INSERT INTO evaluations(track,entity_id,period,score,result,notes,evaluator,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(track,entity_id,period) DO UPDATE SET score=excluded.score,result=excluded.result,notes=excluded.notes,evaluator=excluded.evaluator,created_at=excluded.created_at',(v.track,v.entity_id,v.period,v.score,result,v.notes,u['id'],now()))
  audit(c,u['id'],'evaluate',v.track,v.entity_id,f'{v.period} {v.score}')
 return {'ok':True,'result':result}

@app.get('/api/audits')
def audits(request:Request):
 u=user(request,allowed=['superadmin','ketum','sekjen','waketum','auditor'])
 with db() as c:return {'items':rows(c,'SELECT a.*,u.full_name as actor_name FROM audits a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 200')}

def stage_excel_bytes(data:bytes,actor_id:int):
 """Stage provided roster with no approvals, no active accounts and no SK issuance."""
 from openpyxl import load_workbook
 if len(data)>3*1024*1024 or not data.startswith(b'PK') :raise HTTPException(422,'Berkas XLSX tidak valid atau terlalu besar (maksimum 3 MB)')
 try:wb=load_workbook(io.BytesIO(data),read_only=True,data_only=True);ws=wb.active
 except Exception:raise HTTPException(422,'Berkas Excel tidak dapat dibaca')
 created=0;blank=0;duplicates=0;last_place={}
 with transaction() as c:
  for r in ws.iter_rows(min_row=13,values_only=True):
   # A=0,B=1,C=2,D=3,E=4,F=5,G=6,H=7,I=8,J=9
   if len(r)<9:continue
   prov=str(r[2] or '').strip();city=str(r[3] or '').strip();title=str(r[4] or '').strip();name=str(r[5] or '').strip();level=str(r[8] or '').strip().upper();phone=str(r[9] or '').strip() if len(r)>9 else ''
   if prov and prov.casefold() not in ('provinsi',):
    if prov!=last_place.get('province'):last_place={'province':prov,'city':''}
    else:last_place['province']=prov
   if city:last_place['city']=city
   if level not in ORGS or title.lower() not in ('ketua','sekretaris','bendahara') or not prov:continue
   if not name:blank+=1;continue
   loc='' if level=='DPW' else city or last_place.get('city','')
   # Never merge by name alone. Staging entries are separate until manual identity reconciliation.
   existing=row(c,'''SELECT a.id FROM appointments a JOIN people p ON p.id=a.person_id WHERE lower(p.full_name)=lower(?) AND a.level=? AND a.province=? AND a.city=? AND lower(a.title)=lower(?) LIMIT 1''',(name,level,prov,loc,title))
   if existing:duplicates+=1;continue
   c.execute('INSERT INTO people(full_name,phone,created_at,created_by,status) VALUES(?,?,?,?,?)',(name,phone,now(),actor_id,'draft'))
   pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
   c.execute('INSERT INTO appointments(person_id,level,province,city,title,status,created_at) VALUES(?,?,?,?,?,?,?)',(pid,level,prov,loc,title.title(),'draft',now()));created+=1
  audit(c,actor_id,'import_staging','people',0,f'import={created}, duplicates={duplicates}, blank={blank}')
 return {'ok':True,'created':created,'duplicates':duplicates,'blank':blank,'message':'Semua hasil impor berstatus draft dan memerlukan pemeriksaan per orang. Tidak ada SK/KTA yang otomatis disahkan.'}


@app.post('/api/import-excel')
async def import_excel(request:Request,file:UploadFile=File(...)):
 """Data_SK_WIB.xlsx: SK terbit pada tanggal di kolom TANGGAL (baris tanpa tanggal masuk draft). Format lama: semua masuk draft."""
 u=user(request,True,['superadmin','admin_wib'])
 data=await file.read(10*1024*1024+1)
 if len(data)>10*1024*1024 or not data.startswith(b'PK'):raise HTTPException(422,'Berkas XLSX tidak valid atau terlalu besar (maksimum 10 MB)')
 try:records=await run_in_threadpool(sk_wib.read_data_sk,data)
 except ValueError as e:raise HTTPException(422,str(e))
 if records is None:return stage_excel_bytes(data,u['id'])
 return await run_in_threadpool(import_data_sk,records,u['id'],Path(file.filename or '').name[:80])

def issue_wib_sk(c,aid,a,prov,reg,when,person_id,skno=None):
 """Terbitkan SK WIB aktif bertanggal `when` untuk jabatan `aid`. Nomor `skno` (mis. disalin dari SK lama)
 dipakai apa adanya; bila kosong disusun dari kode wilayah sesuai aturan DPP."""
 skno=skno or sk_wib.sk_number(a,prov,reg,when)
 member=row(c,"SELECT member_no FROM appointments WHERE person_id=? AND member_no IS NOT NULL ORDER BY id LIMIT 1",(person_id,))
 memberno=member['member_no'] if member else nextno(c,'member','WIB-{year}-{n:06d}')
 c.execute("UPDATE appointments SET status='active',member_no=?,sk_no=?,started_at=?,approved_at=?,prov_code=?,city_code=?,periode=COALESCE(periode,?) WHERE id=?",(memberno,skno,when.isoformat(),now(),prov['kode'] if prov else None,reg['kode'] if reg else None,default_periode(when),aid))
 c.execute("UPDATE people SET status='active' WHERE id=?",(person_id,))
 if a['title'].lower()=='ketua':
  c.execute('INSERT OR IGNORE INTO ses_assignments(person_id,wib_appointment_id,ses_role,region,status,created_at) VALUES(?,?,?,?,?,?)',(person_id,aid,SES_ROLE[a['level']],a['city'] or a['province'],'draft',now()))
 return skno,memberno

def import_data_sk(records,actor_id,filename=''):
 """Data_SK_WIB.xlsx sebagai database pengurus. Baris dengan TANGGAL langsung aktif: nomornya NOMOR_SK bila diisi
 (disalin apa adanya), selain itu disusun dari kode wilayah dengan bulan & tahun TANGGAL. Baris tanpa TANGGAL,
 PAC tanpa NOMOR_SK, dan baris berkode belum lengkap masuk draft. Impor ulang melengkapi draft yang sudah ada
 dan memperbarui tanggal/nomor SK aktif yang berubah."""
 res={'ok':True,'format':'data_sk','active':0,'draft':0,'updated':0,'duplicates':0,'blank':0,'skipped':[],'drafts':[]}
 with transaction() as c:
  for d in records:
   why=sk_wib.data_sk_skip_reason(d)
   if why:
    if why.startswith('Nama kosong'):res['blank']+=1
    else:res['skipped'].append([d['_row'],d['NAMA'],why])
    continue
   lvl=d['TINGKAT'];title=d['JABATAN'].strip().title()
   prov=sk_wib.find_province(d['PROVINSI']);province=sk_wib.nice(prov['nama'] if prov else d['PROVINSI'])
   city=district='';sebutan=None
   if lvl in ('DPD','DPC'):
    reg=sk_wib.find_region(prov,lvl,d['WILAYAH_NAMA']);city=(sk_wib.nice(f"{reg['jenis']} {reg['nama']}") if reg else sk_wib.nice(('Kabupaten ' if lvl=='DPD' else 'Kota ')+d['WILAYAH_NAMA']))
   elif lvl=='PAC':
    district=sk_wib.nice(d['WILAYAH_NAMA']);city=sk_wib.nice(d['WILAYAH_INDUK']);sebutan=d['SEBUTAN_KHUSUS'].upper() or None
   when=d['_tanggal'];given=d['NOMOR_SK']
   a={'level':lvl,'province':province,'city':city,'district':district,'title':title,'sebutan':sebutan}
   prov,reg=sk_wib.resolve_codes(a);problem=sk_wib.code_problem(a,prov,reg)
   if lvl=='PAC' and given:problem=None  # nomor PAC disalin dari SK lama
   old=row(c,'''SELECT a.* FROM appointments a JOIN people p ON p.id=a.person_id WHERE lower(p.full_name)=lower(?) AND a.level=? AND a.province=? AND a.city=? AND a.district=? AND lower(a.title)=lower(?) AND a.status IN ('draft','active') ORDER BY a.status='active' DESC LIMIT 1''',(d['NAMA'],lvl,province,city,district,title))
   if old:
    # impor ulang: lengkapi draft yang kini bertanggal, atau perbarui tanggal/nomor SK aktif
    can=when and not problem and (lvl!='PAC' or given)
    seat=row(c,"SELECT id FROM appointments WHERE level=? AND province=? AND city=? AND district=? AND title=? AND status='active' AND id<>? LIMIT 1",(lvl,province,city,district,title,old['id']))
    skno=given or (sk_wib.sk_number(a,prov,reg,when) if can else None)
    if can and not seat and (old['status']=='draft' or old['started_at']!=when.isoformat() or old['sk_no']!=skno):
     was=old['status'];issue_wib_sk(c,old['id'],a,prov,reg,when,old['person_id'],skno)
     res['active' if was=='draft' else 'updated']+=1
    else:res['duplicates']+=1
    continue
   seat=row(c,"SELECT id FROM appointments WHERE level=? AND province=? AND city=? AND district=? AND title=? AND status='active' LIMIT 1",(lvl,province,city,district,title))
   active=bool(when) and (lvl!='PAC' or bool(given)) and not problem and not seat
   gender={'L':'Laki-laki','P':'Perempuan'}.get(d['JK'].upper()[:1],'')
   c.execute('INSERT INTO people(full_name,phone,gender,created_at,created_by,status) VALUES(?,?,?,?,?,?)',(d['NAMA'],d['NO_HP'],gender,now(),actor_id,'active' if active else 'draft'))
   pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
   c.execute('INSERT INTO appointments(person_id,level,province,city,district,title,status,created_at,prov_code,city_code,sebutan) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
    (pid,lvl,province,city,district,title,'draft',now(),prov['kode'] if prov else None,reg['kode'] if reg else None,sebutan))
   aid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
   if not active:
    res['draft']+=1
    why='Kursi sudah diisi pengurus aktif' if seat else problem or ((f"TANGGAL '{d['TANGGAL']}' tidak terbaca" if d['TANGGAL'] else 'TANGGAL belum diisi') if not when else 'PAC: isi NOMOR_SK (format nomor PAC belum ditetapkan)')
    res['drafts'].append([d['_row'],d['NAMA'],why])
    continue
   issue_wib_sk(c,aid,a,prov,reg,when,pid,given or None);res['active']+=1
  audit(c,actor_id,'import_data_sk','people',0,f"{filename}: aktif={res['active']}, diperbarui={res['updated']}, draft={res['draft']}, duplikat={res['duplicates']}, kosong={res['blank']}, dilewati={len(res['skipped'])}")
 res['message']=('Tanggal dan bulan SK mengikuti kolom TANGGAL; NOMOR_SK yang diisi disalin apa adanya. '
  f"{res['draft']} baris masuk draft karena TANGGAL belum diisi atau perlu dicek."+(f" {res['updated']} SK aktif diperbarui tanggal/nomornya." if res['updated'] else ''))
 return res

@app.get('/api/export-people.csv')
def export_people(request:Request):
 u=user(request,allowed=['superadmin','admin_wib','ketum','sekjen','waketum','auditor'])
 out=io.StringIO();w=csv.writer(out);w.writerow(['Nama','Tingkat','Provinsi','Kabupaten/Kota','Kecamatan','Jabatan','Status','Nomor Anggota','Nomor SK','Keaktifan','Keterangan Keaktifan'])
 with db() as c:
  for a in rows(c,'SELECT a.*,p.full_name FROM appointments a JOIN people p ON p.id=a.person_id ORDER BY a.province,a.level'):
   values=[a['full_name'],a['level'],a['province'],a['city'],a['district'],a['title'],a['status'],a['member_no'],a['sk_no'],'Tidak aktif' if a['activity_status']=='tidak_aktif' else 'Aktif',a['activity_note'] or '']
   w.writerow(["'"+str(x) if x and str(x)[0] in '=+-@' else x for x in values])
 return Response(out.getvalue(),media_type='text/csv; charset=utf-8',headers={'Content-Disposition':'attachment; filename="rekap_wib.csv"'})


def document_pdf(track,id,kind,request,download=False):
 u=user(request)
 with db() as c:
  if track=='WIB':
   a=row(c,'SELECT a.*,p.full_name FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.id=?',(id,))
   if not a:raise HTTPException(404,'SK WIB tidak ditemukan')
   if u['role']=='dpw' and u['region']!=a['province']:raise HTTPException(403,'Di luar wilayah')
   if u['role'] in ('ses_admin','ses_pic','ses_director') and not row(c,"SELECT id FROM ses_assignments WHERE person_id=? AND status='active'",(a['person_id'],)):
    raise HTTPException(403,'SK WIB hanya tersedia untuk penerima SK SES aktif')
   if kind=='SK':return wib_sk_response(c,a,download)
   if kind=='DOCX':return wib_docx_response(c,a)
   issued=a['status'] in ('active','inactive') and bool(a['sk_no']);reference=a['sk_no'] or 'DRAFT — BELUM DISAHKAN'
   fullname=a['full_name'];title=a['title']+' '+a['level'];place=' / '.join(x for x in (a['district'],a['city'],a['province']) if x);member=a['member_no'] or 'BELUM TERBIT'
  else:
   a=row(c,'SELECT s.*,p.full_name,w.province FROM ses_assignments s JOIN people p ON p.id=s.person_id JOIN appointments w ON w.id=s.wib_appointment_id WHERE s.id=?',(id,))
   if not a:raise HTTPException(404,'SK SES tidak ditemukan')
   if u['role']=='dpw' and u['region']!=a['province']:raise HTTPException(403,'Di luar wilayah')
   if a['ses_role'] in SES_TEMPLATES and SES_TEMPLATES[a['ses_role']].exists():return ses_doc_response(c,a,kind,download)
   if kind=='DOCX':raise HTTPException(404,'Template Word SK SES untuk jabatan ini belum tersedia')
   issued=a['status'] in ('active','inactive') and bool(a['sk_no']);reference=a['sk_no'] or 'DRAFT — BELUM DISAHKAN';fullname=a['full_name'];title=a['ses_role'];place=a['region'];member='—'
  buffer=io.BytesIO();width,height=(landscape((85.6*2.83465,54*2.83465)) if kind=='KTA' else A4)
  cv=canvas.Canvas(buffer,pagesize=(width,height))
  def tx(y,s,x=56,size=11,color='#1e293b',bold=False):
   cv.setFont('Helvetica-Bold' if bold else 'Helvetica',size);cv.setFillColor(HexColor(color));cv.drawString(x,y,s[:98])
  if kind=='KTA':
   cv.setFillColor(HexColor('#f9fafb'));cv.rect(0,0,width,height,fill=1,stroke=0)
   cv.setFillColor(HexColor('#bd2027'));cv.rect(0,height-38,width,38,fill=1,stroke=0)
   tx(height-24,'WAKTU INDONESIA BERGERAK',13,11,'#ffffff',True)
   tx(height-58,'KARTU TANDA ANGGOTA',11,12,'#111827',True)
   tx(height-77,fullname.upper(),13,12,'#111827',True)
   tx(height-92,title+' — '+place,9,12)
   tx(height-108,member,10,12,'#bd2027',True)
   qr=qrcode.make(f'WIB:{member}:STATUS:{a["status"]}');q=io.BytesIO();qr.save(q,format='PNG');q.seek(0)
   from reportlab.lib.utils import ImageReader
   cv.drawImage(ImageReader(q),width-86,13,66,66)
   if not issued:tx(26,'CONTOH / TIDAK BERLAKU',9,12,'#c2410c',True)
  else:
   cv.setFillColor(HexColor('#bd2027' if track=='WIB' else '#176b61'));cv.rect(0,height-105,width,105,fill=1,stroke=0)
   tx(height-52,'WAKTU INDONESIA BERGERAK (WIB)' if track=='WIB' else 'SES GROUP',17,56,'#ffffff',True)
   tx(height-78,'SURAT KEPUTUSAN / PENUGASAN',12,56,'#ffffff')
   tx(height-163,'Nomor: '+reference,size=12,bold=True)
   tx(height-208,'TENTANG PENGANGKATAN / PENUGASAN',size=13,bold=True)
   tx(height-254,'Nama             : '+fullname,size=12)
   tx(height-285,'Jabatan         : '+title,size=12)
   tx(height-316,'Wilayah          : '+place,size=12)
   tx(height-347,'Status           : '+('Aktif' if a['status']=='active' else 'Tidak aktif' if a['status']=='inactive' else 'Draft'),size=12)
   tx(height-398,'Diterbitkan sebagai bukti administrasi sistem.',size=11)
   tx(height-418,'Keabsahan keputusan harus diperiksa pada pejabat penandatangan.',size=10)
   tx(height-468,'Tanggal sistem: '+today(),size=10)
   if not issued:
    cv.saveState();cv.setFillColor(HexColor('#cbd5e1'));cv.translate(width/2,height/2);cv.rotate(36);cv.setFont('Helvetica-Bold',52);cv.drawCentredString(0,0,'DRAFT');cv.restoreState()
   cv.setFillColor(HexColor('#64748b'));cv.setFont('Helvetica',8);cv.drawString(56,42,'Dokumen aplikasi internal. Tidak memuat tanda tangan elektronik tersertifikasi.')
  cv.showPage();cv.save();buffer.seek(0)
  return StreamingResponse(buffer,media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="{track}-{kind}-{id}.pdf"'})
@app.get('/api/pdf/{track}/{id}/{kind}')
def get_pdf(track:str,id:int,kind:str,request:Request,download:int=0):
 if kind=='KTA' and not KTA_ENABLED:raise HTTPException(404,'Modul KTA WIB ditunda pada versi ini')
 if track not in ('WIB','SES') or kind not in ('SK','KTA','DOCX') or (track=='SES' and kind=='KTA'):raise HTTPException(422,'Jenis dokumen tidak tersedia')
 return document_pdf(track,id,kind,request,bool(download))

# ---------- Generate SK WIB (format resmi) ----------
SK_EDITORS=['superadmin','admin_wib']
SK_VIEWERS=['superadmin','admin_wib','ketum','sekjen','waketum','dpw','auditor']
def sk_template(c):
 r=row(c,"SELECT data FROM sk_templates WHERE track='WIB'")
 return sk_wib.clean_template(json.loads(r['data']) if r else {})
def sk_image(slot):
 return next((p for p in (SK_ASSETS/f'{slot}{ext}' for ext in ('.png','.jpg')) if p.exists()),None)
def undated(nomor):
 """Nomor perkiraan untuk SK draft: bulan & tahun baru diketahui saat SK ditetapkan."""
 return re.sub(r'/[IVX]+/\d{4}$','/…/…',nomor)
def sk_info(c,a):
 """Isi SK satu jabatan: nomor (resmi, atau perkiraan bila masih draft), tanggal, dan teks pengganti."""
 person=row(c,'SELECT full_name,gender FROM people WHERE id=?',(a['person_id'],))
 prov,reg=sk_wib.resolve_codes(a)
 issued=a['status'] in ('active','inactive') and bool(a['sk_no'])
 when=datetime.fromisoformat((a['started_at'] or a['approved_at'])[:10]).date() if issued and (a['started_at'] or a['approved_at']) else datetime.now(TZ).date()
 nomor=a['sk_no'] if issued else undated(sk_wib.sk_number(a,prov,reg,when) or '…/SK-DPP/'+a['level'])+' (DRAFT)'
 return dict(sk_wib.sk_fields(a,person,prov,reg),nomor=nomor,draft=not issued,tanggal=when),prov,reg
def sk_filename(a,info,ext):
 """Format nama file: SK WIB <JABATAN> <DPW/DPD/DPC/PAC> <DAERAH>, mis. 'SK WIB KETUA DPW JAWA BARAT.pdf'.
 DAERAH = wilayah pada diktum KESATU (DPW: provinsi; DPD/DPC: kabupaten/kota; PAC: kecamatan + kab/kota induk).
 SK yang belum ditetapkan diberi akhiran (DRAFT) agar tidak tertukar dengan SK resmi."""
 import unicodedata
 base=f"SK WIB {info['jabatan']} {a['level']} {info['wilayah_kesatu']}".upper()+(' (DRAFT)' if info.get('draft') else '')
 base=unicodedata.normalize('NFKD',base).encode('ascii','ignore').decode()
 base=re.sub(r'[\\/:*?"<>|\x00-\x1f]+',' ',base)
 base=re.sub(r'\s+',' ',base).strip(' .')[:150]
 return base+ext
def sk_images(c):
 """Gambar template SK. Slot di sk_wib.AUTH_SLOTS (kini kosong) hanya dipakai bila berkasnya telah diotorisasi."""
 out={k:sk_image(k) for k in sk_wib.IMAGE_SLOTS}
 for k in sk_wib.AUTH_SLOTS:
  if out[k] and not image_authorized(c,k,out[k]):out[k]=None
 return out
def image_authorized(c,slot,path):
 r=row(c,'SELECT sha1 FROM sk_image_auth WHERE slot=?',(slot,))
 return bool(r and path and r['sha1']==hashlib.sha1(path.read_bytes()).hexdigest())
def wib_docx_response(c,a):
 if not SK_DOCX.exists():raise HTTPException(404,'Template Word SK belum diunggah. Unggah di menu Generate SK > Template SK.')
 info,_,_=sk_info(c,a)
 values=sk_wib.docx_values(info)
 data=docx_sk.fill(SK_DOCX.read_bytes(),values)
 return StreamingResponse(io.BytesIO(data),media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',headers={'Content-Disposition':f'attachment; filename="{sk_filename(a,info,".docx")}"'})
def wib_sk_response(c,a,download=False):
 info,_,_=sk_info(c,a)
 pdf=sk_wib.render_pdf(info,sk_template(c),sk_images(c))
 name=sk_filename(a,info,'.pdf')
 return StreamingResponse(io.BytesIO(pdf),media_type='application/pdf',headers={'Content-Disposition':f'{"attachment" if download else "inline"}; filename="{name}"'})

@app.get('/api/sk/wib')
def sk_list(request:Request,q:str='',level:str='',province:str='',status:str='',code:str='',page:int=1,limit:int=20):
 u=user(request,allowed=SK_VIEWERS);page=max(1,page);limit=min(max(limit,1),100)
 where=["a.status IN ('draft','active','inactive')"];args=[]
 if q:where.append('(p.full_name LIKE ? OR a.city LIKE ? OR a.district LIKE ? OR a.sk_no LIKE ?)');args.extend(['%'+q+'%']*4)
 if level in ORGS:where.append('a.level=?');args.append(level)
 if province:where.append('a.province=?');args.append(province)
 if status in ('draft','active','inactive'):where.append('a.status=?');args.append(status)
 if u['role']=='dpw':where.append('a.province=?');args.append(u['region'])
 filt='WHERE '+' AND '.join(where)
 with db() as c:
  data=rows(c,f'SELECT a.*,p.full_name,p.gender FROM appointments a JOIN people p ON p.id=a.person_id {filt} ORDER BY a.province,a.level,a.city,a.id',args)
  items=[]
  for a in data:
   info,prov,reg=sk_info(c,a);problem=sk_wib.code_problem(a,prov,reg)
   if (code=='missing' and not problem) or (code=='ok' and problem):continue
   items.append({'id':a['id'],'person_id':a['person_id'],'full_name':a['full_name'],'title':a['title'],'level':a['level'],'province':a['province'],'city':a['city'],'district':a['district'],'status':a['status'],
    'nomor':info['nomor'],'wilayah':info['wilayah_judul'],'prov_code':prov['kode'] if prov else None,'city_code':reg['kode'] if reg else None,
    'region_label':(f"{prov['kode']} {prov['nama']}" if prov else '')+(f" · {reg['kode']} {reg['jenis']} {reg['nama']}" if reg else ''),'problem':problem})
  provinces=[x['province'] for x in rows(c,'SELECT DISTINCT province FROM appointments ORDER BY province')]
  if u['role']=='dpw':provinces=[x for x in provinces if x==u['region']]
 total=len(items);missing=sum(1 for x in items if x['problem'])
 return {'items':items[(page-1)*limit:page*limit],'total':total,'missing':missing,'page':page,'pages':math.ceil(total/limit),'provinces':provinces,'can_edit':u['role'] in SK_EDITORS}

@app.get('/api/sk/reference')
def sk_reference(request:Request):
 user(request,allowed=SK_VIEWERS)
 return {'provinsi':[{'kode':p['kode'],'nama':p['nama'],'wilayah':[{'kode':w['kode'],'jenis':w['jenis'],'nama':w['nama']} for w in p['wilayah']]} for p in sk_wib.REF['provinsi']]}

class RegionCode(BaseModel):prov_code:str;city_code:str=''
@app.post('/api/appointments/{id}/region-code')
def set_region_code(id:int,v:RegionCode,request:Request):
 u=user(request,True,SK_EDITORS)
 prov=sk_wib.province_by_code(v.prov_code)
 if not prov:raise HTTPException(422,'Kode provinsi tidak dikenal')
 with transaction() as c:
  a=row(c,'SELECT * FROM appointments WHERE id=?',(id,))
  if not a:raise HTTPException(404,'Jabatan tidak ditemukan')
  if a['status']!='draft':raise HTTPException(409,'Kode wilayah hanya dapat diubah sebelum SK disahkan')
  reg=None
  if a['level']!='DPW':
   reg=sk_wib.region_by_code(prov,v.city_code)
   if not reg:raise HTTPException(422,'Pilih kabupaten/kota dari daftar kode')
  c.execute('UPDATE appointments SET prov_code=?,city_code=? WHERE id=?',(prov['kode'],reg['kode'] if reg else None,id))
  audit(c,u['id'],'set_region_code','appointment',id,f"{prov['kode']} {prov['nama']}"+(f" / {reg['kode']} {reg['jenis']} {reg['nama']}" if reg else ''))
 return {'ok':True}

@app.get('/api/sk/template')
def sk_template_get(request:Request):
 u=user(request,allowed=SK_VIEWERS)
 with db() as c:
  r=row(c,"SELECT t.updated_at,u.full_name FROM sk_templates t LEFT JOIN users u ON u.id=t.updated_by WHERE track='WIB'")
  auth={x['slot']:x for x in rows(c,'SELECT * FROM sk_image_auth')}
  def img_state(k):
   p=sk_image(k);a=auth.get(k)
   return {'label':sk_wib.IMAGE_SLOTS[k],'present':bool(p),'needs_auth':k in sk_wib.AUTH_SLOTS,'authorized':bool(p and a and a['sha1']==hashlib.sha1(p.read_bytes()).hexdigest()),'authorized_by':a['authorized_name'] if a else None,'authorized_at':a['authorized_at'] if a else None}
  return {'template':sk_template(c),'images':{k:img_state(k) for k in sk_wib.IMAGE_SLOTS},'can_authorize':u['role'] in ('superadmin','ketum'),'updated_at':r['updated_at'] if r else None,'updated_by':r['full_name'] if r else None,'can_edit':u['role'] in SK_EDITORS,
   'docx':{'present':SK_DOCX.exists(),'fields':sorted(docx_sk.template_fields(SK_DOCX.read_bytes())) if SK_DOCX.exists() else []}}
@app.post('/api/sk/template')
async def sk_template_save(request:Request):
 u=user(request,True,SK_EDITORS)
 try:data=await request.json()
 except Exception:raise HTTPException(422,'Data template tidak valid')
 if not isinstance(data,dict):raise HTTPException(422,'Data template tidak valid')
 tpl=sk_wib.clean_template(data)
 with transaction() as c:
  c.execute("INSERT INTO sk_templates(track,data,updated_at,updated_by) VALUES('WIB',?,?,?) ON CONFLICT(track) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at,updated_by=excluded.updated_by",(safe_json(tpl),now(),u['id']))
  audit(c,u['id'],'update_sk_template','sk_template',0,'Template SK WIB diperbarui')
 return {'ok':True,'template':tpl}
@app.post('/api/sk/template/reset')
def sk_template_reset(request:Request):
 u=user(request,True,SK_EDITORS)
 with transaction() as c:
  c.execute("DELETE FROM sk_templates WHERE track='WIB'");audit(c,u['id'],'reset_sk_template','sk_template',0,'Teks template SK WIB dikembalikan ke bawaan')
 return {'ok':True}
@app.post('/api/sk/template/image/{slot}/authorize')
def sk_image_authorize(slot:str,request:Request):
 """Ketua Umum mengotorisasi gambar tanda tangan/stempel resmi yang terpasang saat ini."""
 u=user(request,True,['superadmin','ketum'])
 if slot not in sk_wib.AUTH_SLOTS:raise HTTPException(404,'Gambar ini tidak memerlukan otorisasi')
 path=sk_image(slot)
 if not path:raise HTTPException(404,'Gambar belum diunggah')
 digest=hashlib.sha1(path.read_bytes()).hexdigest()
 with transaction() as c:
  c.execute('INSERT INTO sk_image_auth(slot,sha1,authorized_by,authorized_name,authorized_at) VALUES(?,?,?,?,?) ON CONFLICT(slot) DO UPDATE SET sha1=excluded.sha1,authorized_by=excluded.authorized_by,authorized_name=excluded.authorized_name,authorized_at=excluded.authorized_at',(slot,digest,u['id'],u['full_name'],now()))
  audit(c,u['id'],'authorize_sk_image','sk_template',0,f'{slot} sha1={digest[:12]}')
 return {'ok':True}
@app.post('/api/sk/template/image/{slot}/revoke')
def sk_image_revoke(slot:str,request:Request):
 u=user(request,True,['superadmin','ketum'])
 with transaction() as c:
  c.execute('DELETE FROM sk_image_auth WHERE slot=?',(slot,));audit(c,u['id'],'revoke_sk_image','sk_template',0,slot)
 return {'ok':True}
@app.get('/api/sk/template/image/{slot}')
def sk_image_get(slot:str,request:Request):
 user(request,allowed=SK_VIEWERS)
 path=sk_image(slot) if slot in sk_wib.IMAGE_SLOTS else None
 if not path:raise HTTPException(404,'Gambar belum diunggah')
 return FileResponse(path,media_type='image/png' if path.suffix=='.png' else 'image/jpeg')
@app.post('/api/sk/template/image/{slot}')
async def sk_image_upload(slot:str,request:Request,file:UploadFile=File(...)):
 u=user(request,True,SK_EDITORS)
 if slot not in sk_wib.IMAGE_SLOTS:raise HTTPException(404,'Jenis gambar tidak dikenal')
 content=await file.read(3*1024*1024+1)
 if len(content)>3*1024*1024:raise HTTPException(413,'Ukuran maksimum 3 MB')
 if content.startswith(b'\x89PNG'):ext='.png'
 elif content.startswith(b'\xff\xd8'):ext='.jpg'
 else:raise HTTPException(422,'Unggah gambar PNG atau JPG')
 for old in ('.png','.jpg'):(SK_ASSETS/f'{slot}{old}').unlink(missing_ok=True)
 (SK_ASSETS/f'{slot}{ext}').write_bytes(content)
 with transaction() as c:audit(c,u['id'],'upload_sk_image','sk_template',0,sk_wib.IMAGE_SLOTS[slot])
 return {'ok':True}

class NewSK(BaseModel):
 full_name:str=Field(min_length=3,max_length=160);gender:str='';phone:str=''
 level:str;title:str;prov_code:str;city_code:str='';district:str='';sebutan:str='';tanggal:str='';replace:bool=False
def new_sk_plan(c,v):
 """Validasi isian Buat SK Baru. Hasil: dict jabatan, kode, nomor SK, judul wilayah, dan pejabat aktif di kursi yang sama."""
 if v.level not in ORGS:raise HTTPException(422,'Tingkat tidak dikenal')
 title=v.title.strip().title()
 if title.lower() not in sk_wib.JABATAN_KODE:raise HTTPException(422,'Jabatan tidak dikenal')
 prov=sk_wib.province_by_code(v.prov_code)
 if not prov:raise HTTPException(422,'Pilih provinsi')
 reg=None;city=district=''
 if v.level!='DPW':
  reg=sk_wib.region_by_code(prov,v.city_code)
  if not reg:raise HTTPException(422,'Pilih kabupaten/kota')
  if v.level=='DPD' and reg['jenis']!='KABUPATEN':raise HTTPException(422,'DPD untuk kabupaten; pilih kabupaten atau gunakan tingkat DPC untuk kota')
  if v.level=='DPC' and reg['jenis']!='KOTA':raise HTTPException(422,'DPC untuk kota; pilih kota atau gunakan tingkat DPD untuk kabupaten')
  city=sk_wib.nice(f"{reg['jenis']} {reg['nama']}")
 if v.level=='PAC':
  district=sk_wib.nice(v.district)
  if not district:raise HTTPException(422,'Kecamatan/distrik wajib diisi untuk PAC')
 try:when=datetime.strptime(v.tanggal,'%Y-%m-%d').date() if v.tanggal else datetime.now(TZ).date()
 except ValueError:raise HTTPException(422,'Tanggal SK tidak valid')
 a={'level':v.level,'province':sk_wib.nice(prov['nama']),'city':city,'district':district,'title':title,'sebutan':v.sebutan.strip().upper() or None}
 holder=row(c,"SELECT a.id,p.full_name,a.sk_no FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.level=? AND a.province=? AND a.city=? AND a.district=? AND a.title=? AND a.status='active' LIMIT 1",(a['level'],a['province'],city,district,title))
 same=row(c,"SELECT a.id,a.status FROM appointments a JOIN people p ON p.id=a.person_id WHERE lower(p.full_name)=lower(?) AND a.level=? AND a.province=? AND a.city=? AND a.district=? AND a.title=? AND a.status IN ('active','draft') LIMIT 1",(v.full_name.strip(),a['level'],a['province'],city,district,title))
 f=sk_wib.sk_fields(a,{'full_name':v.full_name,'gender':'Perempuan' if v.gender.upper()=='P' else ''},prov,reg)
 return {'a':a,'prov':prov,'reg':reg,'when':when,'nomor':sk_wib.sk_number(a,prov,reg,when),'wilayah':f['wilayah_judul'],'kesatu':f"{f['sapaan']} {f['nama']} sebagai {f['jabatan']} {f['tingkat_lengkap']} {f['wilayah_kesatu']}",'holder':holder,'same':same}
@app.post('/api/sk/new/preview')
def sk_new_preview(v:NewSK,request:Request):
 user(request,True,SK_EDITORS)
 with db() as c:x=new_sk_plan(c,v)
 return {'nomor':x['nomor'] or 'Draft — format nomor PAC belum ditetapkan','wilayah':x['wilayah'],'kesatu':x['kesatu'],'tanggal':sk_wib.tanggal_teks(x['when']),
  'holder':x['holder'],'same':bool(x['same']),'draft':x['nomor'] is None}
def create_new_sk(c,u,v,label=''):
 """Simpan satu SK baru di dalam transaksi `c`. `label` (mis. 'Sekretaris') ditambahkan pada pesan kesalahan."""
 pre=f'{label}: ' if label else ''
 x=new_sk_plan(c,v);a=x['a']
 if x['same']:raise HTTPException(409,f"{pre}{v.full_name.strip()} sudah tercatat pada jabatan ini. Buka data yang ada di tabel Generate SK.")
 if x['holder'] and not v.replace:raise HTTPException(409,f"{pre}Kursi ini masih diisi {x['holder']['full_name']} ({x['holder']['sk_no']}). Centang 'Gantikan pejabat lama' untuk mengakhiri jabatannya.")
 if x['holder']:
  old=row(c,'SELECT * FROM appointments WHERE id=?',(x['holder']['id'],))
  c.execute("UPDATE appointments SET status='inactive',ended_at=?,end_reason='penggantian' WHERE id=?",(x['when'].isoformat(),old['id']))
  if not row(c,"SELECT id FROM appointments WHERE person_id=? AND status='active'",(old['person_id'],)):c.execute("UPDATE people SET status='inactive' WHERE id=?",(old['person_id'],))
  audit(c,u['id'],'terminate_wib','appointment',old['id'],'penggantian melalui Buat SK Baru')
 gender={'L':'Laki-laki','P':'Perempuan'}.get(v.gender.upper()[:1],'')
 c.execute('INSERT INTO people(full_name,phone,gender,created_at,created_by,status) VALUES(?,?,?,?,?,?)',(v.full_name.strip(),v.phone.strip(),gender,now(),u['id'],'draft'))
 pid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
 c.execute('INSERT INTO appointments(person_id,level,province,city,district,title,status,created_at,prov_code,city_code,sebutan) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
  (pid,a['level'],a['province'],a['city'],a['district'],a['title'],'draft',now(),x['prov']['kode'],x['reg']['kode'] if x['reg'] else None,a['sebutan']))
 aid=c.execute('SELECT last_insert_rowid()').fetchone()[0];skno=None
 if x['nomor']:skno,_=issue_wib_sk(c,aid,a,x['prov'],x['reg'],x['when'],pid)
 audit(c,u['id'],'create_sk_new','appointment',aid,f"{skno or 'draft PAC'} {v.full_name.strip()}")
 return {'id':aid,'person_id':pid,'sk_no':skno,'status':'active' if skno else 'draft','full_name':v.full_name.strip(),'title':a['title']}
@app.post('/api/sk/new')
def sk_new(v:NewSK,request:Request):
 """Buat SK WIB baru: orang & jabatan disimpan ke database, SK langsung terbit (PAC: draft)."""
 u=user(request,True,SK_EDITORS)
 with transaction() as c:r=create_new_sk(c,u,v)
 return dict(r,ok=True)

@app.get('/api/sk/coverage')
def sk_coverage(request:Request):
 """Jabatan aktif per kode wilayah: DPW per provinsi, DPD/DPC per kab/kota (untuk penanda wilayah kosong)."""
 user(request,allowed=SK_EDITORS)
 out={'DPW':{},'DPD':{},'DPC':{}}
 with db() as c:
  for a in rows(c,"SELECT level,province,city,district,title,prov_code,city_code FROM appointments WHERE status='active' AND level IN ('DPW','DPD','DPC')"):
   prov,reg=sk_wib.resolve_codes(a)
   if not prov or (a['level']!='DPW' and not reg):continue
   if a['level']=='DPW':out['DPW'].setdefault(prov['kode'],[]).append(a['title'])
   else:out[a['level']].setdefault(prov['kode'],{}).setdefault(reg['kode'],[]).append(a['title'])
 return out

PAKET=('Ketua','Sekretaris','Bendahara')
class PaketOrang(BaseModel):full_name:str='';gender:str='';phone:str=''
class NewSKPaket(BaseModel):
 level:str;prov_code:str;city_code:str='';district:str='';sebutan:str='';tanggal:str='';replace:bool=False
 people:list[PaketOrang]=Field(min_length=3,max_length=3)
def paket_items(v):
 """Isian per jabatan (Ketua, Sekretaris, Bendahara) dari form paket."""
 base=v.model_dump(exclude={'people'})
 return [(t,NewSK(**base,title=t,full_name=o.full_name.strip(),gender=o.gender,phone=o.phone)) for t,o in zip(PAKET,v.people)]
@app.post('/api/sk/new/paket/preview')
def sk_paket_preview(v:NewSKPaket,request:Request):
 user(request,True,SK_EDITORS);out=[]
 with db() as c:
  for t,o in zip(PAKET,v.people):
   x=new_sk_plan(c,NewSK(**v.model_dump(exclude={'people'}),title=t,full_name=o.full_name.strip() or t.upper(),gender=o.gender))
   out.append({'title':t,'nomor':x['nomor'] or 'Draft — format nomor PAC belum ditetapkan','holder':x['holder'],'same':bool(x['same']) and bool(o.full_name.strip())})
 return {'items':out,'wilayah':x['wilayah'],'tanggal':sk_wib.tanggal_teks(x['when'])}
@app.post('/api/sk/new/paket')
def sk_paket(v:NewSKPaket,request:Request):
 """Ketua, Sekretaris, Bendahara sekaligus untuk satu wilayah. Semua tersimpan atau tidak sama sekali."""
 u=user(request,True,SK_EDITORS)
 for t,o in zip(PAKET,v.people):
  if len(o.full_name.strip())<3:raise HTTPException(422,f'{t}: nama wajib diisi (minimal 3 huruf)')
 items=paket_items(v)
 if len({x.full_name.casefold() for _,x in items})<3:raise HTTPException(422,'Nama Ketua, Sekretaris, dan Bendahara tidak boleh sama')
 with transaction() as c:res=[create_new_sk(c,u,x,t) for t,x in items]
 return {'ok':True,'items':res}

@app.get('/api/sk/zip')
def sk_zip(request:Request,ids:str):
 """Word + PDF untuk beberapa SK sekaligus (mis. hasil paket Ketua, Sekretaris, Bendahara)."""
 u=user(request,allowed=SK_EDITORS)
 try:idlist=[int(x) for x in ids.split(',') if x.strip()][:20]
 except ValueError:raise HTTPException(422,'Daftar SK tidak valid')
 import zipfile
 out=io.BytesIO()
 with db() as c,zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  tpl=sk_template(c);images=sk_images(c)
  for i in idlist:
   a=row(c,'SELECT * FROM appointments WHERE id=?',(i,))
   if not a:raise HTTPException(404,f'SK {i} tidak ditemukan')
   info,_,_=sk_info(c,a)
   z.writestr(sk_filename(a,info,'.pdf'),sk_wib.render_pdf(info,tpl,images))
   if SK_DOCX.exists() and not info['draft']:z.writestr(sk_filename(a,info,'.docx'),docx_sk.fill(SK_DOCX.read_bytes(),sk_wib.docx_values(info)))
 return StreamingResponse(io.BytesIO(out.getvalue()),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="SK_WIB_paket_{today()}.zip"'})

@app.get('/api/sk/template/docx')
def sk_docx_get(request:Request):
 user(request,allowed=SK_EDITORS)
 if not SK_DOCX.exists():raise HTTPException(404,'Template Word SK belum diunggah')
 return FileResponse(SK_DOCX,media_type='application/vnd.openxmlformats-officedocument.wordprocessingml.document',filename='Template_SK_WIB.docx')
@app.post('/api/sk/template/docx')
async def sk_docx_upload(request:Request,file:UploadFile=File(...)):
 u=user(request,True,SK_EDITORS)
 data=await file.read(10*1024*1024+1)
 if len(data)>10*1024*1024 or not data.startswith(b'PK'):raise HTTPException(422,'Unggah berkas Word .docx (maksimum 10 MB)')
 try:data=docx_sk.normalize_template(data);fields=docx_sk.template_fields(data)
 except Exception:raise HTTPException(422,'Berkas bukan dokumen Word .docx yang valid')
 missing=[f for f in ('NOMOR_SK','NAMA','JABATAN','TANGGAL_TEKS') if f not in fields]
 if missing:raise HTTPException(422,'Template harus memuat merge field: '+', '.join('«'+f+'»' for f in missing))
 SK_DOCX.write_bytes(data)
 with transaction() as c:audit(c,u['id'],'upload_sk_docx','sk_template',0,'Template Word SK WIB diganti: '+', '.join(sorted(fields)))
 return {'ok':True,'fields':sorted(fields)}

# ---------- Generate SK SES (template Word resmi per jenis) ----------
# Ketua DPW -> Koordinator Wilayah (SK KEPALA KANWIL), Ketua DPD/DPC -> Kepala Cabang (SK KEPALA KANCAB),
# Ketua PAC -> Kepala Unit (SK KEPALA KANTOR UNIT, nomor unit diketik admin).
SES_SK_EDITORS=['superadmin','ses_director']   # impor arsip, template Word
SES_SUBMITTERS=['superadmin','admin_wib']      # Jovi / Febri mengajukan SK SES
SES_CHECKERS=['superadmin','ses_admin']        # Ihsan selaku Petugas SES Group memeriksa
SES_RATIFIERS=['superadmin','ses_director']    # Direksi SES Group / pejabat berkuasa mengesahkan
SES_SK_VIEWERS=['superadmin','ses_director','ses_admin','admin_wib','ketum','sekjen','waketum','dpw','auditor']
DOCX_MIME='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
SES_TEMPLATES={r:SK_ASSETS/f for r,f in sk_ses.TEMPLATE.items()}
def ses_role_arg(jenis):
 if not jenis:return sk_ses.ROLE
 if jenis not in sk_ses.ROLES:raise HTTPException(422,'Jenis SK SES harus Koordinator Wilayah, Kepala Cabang, atau Kepala Unit')
 return jenis
def ses_place(role,a,sp,sw,unit):
 """(teks wilayah di SK, kunci pemegang jabatan, masalah). Satu pemegang aktif per provinsi (Koordinator Wilayah),
 per kab/kota (Kepala Cabang), atau per nomor unit di satu kab/kota (Kepala Unit)."""
 if not sp:return None,None,'Provinsi tidak ditemukan pada daftar kode wilayah SES'
 if role==sk_ses.ROLE_WIL:return sp['tampil'],(role,sp['kode']),None
 if not sw:return None,None,'Kab/kota tidak ditemukan pada daftar kode wilayah SES'
 if role!=sk_ses.ROLE_UNIT:return sw['tampil'],(role,sp['kode'],sw['kode']),None
 if not unit:return None,None,'Nomor unit belum diisi'
 name=sk_ses.unit_name(a.get('district'),sw)
 if not name:return None,None,'Kecamatan PAC belum tercatat pada jabatan WIB'
 return name,(role,sp['kode'],sw['kode'],unit),None
SES_JOIN="""SELECT s.*,p.full_name,a.level,a.title,a.province,a.city,a.district,a.prov_code,a.city_code FROM ses_assignments s JOIN people p ON p.id=s.person_id
   JOIN appointments a ON a.id=s.wib_appointment_id"""
def ses_holders(c):
 """Pemegang SK SES aktif: {kunci dari ses_place: penugasan}."""
 out={}
 for s in rows(c,SES_JOIN+" WHERE s.status='active' AND s.ses_role IN (?,?,?)",sk_ses.ROLES):
  sp,sw=sk_ses.resolve(s);_,key,_=ses_place(s['ses_role'],s,sp,sw,s['ses_unit_code'])
  if key:out.setdefault(key,s)
 return out
def ses_wib_pengurus(c,with_draft=False):
 """Pengurus WIB aktif (atau juga draft) tingkat DPD/DPC per kab/kota SES (untuk impor Kepala Cabang)."""
 out={}
 states="'active','draft'" if with_draft else "'active'"
 for a in rows(c,f"SELECT a.*,p.full_name,p.gender FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.status IN ({states}) AND a.level IN ('DPD','DPC') ORDER BY a.status='active' DESC,a.id"):
  sp,sw=sk_ses.resolve(a)
  if sw:out.setdefault((sp['kode'],sw['kode']),[]).append(a)
 return out
def ses_ketua(c,role):
 """Ketua WIB aktif calon penerima SK SES `role`: [(jabatan, provinsi SES, kab/kota SES)]."""
 lv=sk_ses.ROLE_LEVELS[role];out=[]
 for a in rows(c,f"SELECT a.*,p.full_name,p.gender FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.status='active' AND lower(trim(a.title))='ketua' AND a.level IN ({','.join('?'*len(lv))}) ORDER BY p.full_name",lv):
  sp,sw=sk_ses.resolve(a)
  if sp and (role==sk_ses.ROLE_WIL or sw):out.append((a,sp,sw))
 return out
def register_ses_number(c,skno,sid):
 c.execute('INSERT INTO sk_numbers(track,sk_no,ref_id,issued_at) VALUES(?,?,?,?)',('SES',skno,sid,now()))
def unique_ses_number(c,base,sid):
 """Nomor SK SES tidak boleh dipakai ulang. Bila nomor dasar (wilayah + bulan) sudah pernah terbit, misalnya
 penggantian pada bulan yang sama, sistem menambah akhiran -2, -3, ... sebelum /SES-GROUP."""
 used=lambda n:(r:=row(c,"SELECT ref_id FROM sk_numbers WHERE track='SES' AND sk_no=?",(n,))) and r['ref_id']!=sid
 if not used(base):return base
 head,tail=base.split('/',1);k=2
 while used(f'{head}-{k}/{tail}'):k+=1
 return f'{head}-{k}/{tail}'
def ses_log(c,u,sid,action,frm,to,note=''):
 c.execute('INSERT INTO ses_reviews(assignment_id,action,from_status,to_status,note,actor,actor_name,actor_role,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(sid,action,frm,to,(note or '').strip()[:1000],u['id'] if u else None,u['full_name'] if u else 'Sistem',u['role'] if u else None,now()))
def issue_ses_sk(c,sid,role,sp,sw,unit,wilayah,when,skno=None):
 """Terbitkan SK SES bertanggal `when` untuk penugasan `sid`; `skno` (disalin dari SK lama) dipakai apa adanya,
 selain itu disusun sesuai aturan SES Group dan dijamin unik."""
 skno=skno or unique_ses_number(c,sk_ses.number(role,sp,sw,when,unit),sid)
 c.execute("INSERT OR IGNORE INTO sk_numbers(track,sk_no,ref_id,issued_at) VALUES('SES',?,?,?)",(skno,sid,now()))
 c.execute("UPDATE ses_assignments SET status='active',sk_no=?,started_at=?,approved_at=?,ended_at=NULL,end_reason=NULL,ses_prov_code=?,ses_city_code=?,ses_unit_code=?,region=? WHERE id=?",
  (skno,when.isoformat(),now(),sp['kode'],sw['kode'] if sw else None,unit,wilayah,sid))
 return skno
def ses_info(c,s):
 """Isi SK SES satu penugasan: nomor (resmi, atau perkiraan bila masih draft), tanggal, wilayah SES."""
 a=row(c,'SELECT * FROM appointments WHERE id=?',(s['wib_appointment_id'],)) or {}
 role=s['ses_role'];unit=s.get('ses_unit_code')
 sp,sw=sk_ses.resolve({**a,'ses_prov_code':s.get('ses_prov_code'),'ses_city_code':s.get('ses_city_code')})
 wilayah,key,problem=ses_place(role,a,sp,sw,unit) if role in sk_ses.ROLES else (None,None,'Jenis SK SES tidak dikenal')
 person=row(c,'SELECT full_name,gender FROM people WHERE id=?',(s['person_id'],))
 issued=s['status'] in ('active','inactive') and bool(s['sk_no'])
 when=datetime.fromisoformat((s['started_at'] or s['approved_at'])[:10]).date() if issued and (s['started_at'] or s['approved_at']) else datetime.now(TZ).date()
 nomor=s['sk_no'] if issued else (undated(sk_ses.number(role,sp,sw,when,unit))+' (DRAFT)' if not problem else '…/SES-GROUP (DRAFT)')
 return {'nomor':nomor,'tanggal':when,'prov':sp,'reg':sw,'unit':unit,'role':role,'wilayah':wilayah or s['region'],'key':key,'kode':sk_ses.code(role,sp,sw,unit),
  'person':person,'draft':not issued,'problem':problem}
def ses_template(role):
 p=SES_TEMPLATES.get(role)
 if not p or not p.exists():raise HTTPException(404,f'Template Word SK SES {role} belum diunggah')
 return p
def ses_fill(template,info):
 v=sk_ses.values(info['nomor'],info['person'],info['wilayah'],info['tanggal'])
 return docx_sk.fill(docx_sk.fit_first_page(template,v),v)
def ses_docx(c,s):
 info=ses_info(c,s)
 if info['problem']:raise HTTPException(409,info['problem'])
 return ses_fill(ses_template(info['role']).read_bytes(),info),info
def ses_filename(info,ext):
 return re.sub(r'[^A-Za-z0-9]+','_',f"SK_SES_{info['role']}_{info['wilayah'] or ''}_{info['person']['full_name']}").strip('_')[:110]+ext
def ses_pdf(datas):
 try:return docx_sk.to_pdfs(datas,PDF_CACHE)
 except RuntimeError as ex:raise HTTPException(503,str(ex))
def ses_doc_response(c,s,kind,download=False):
 data,info=ses_docx(c,s)
 if kind=='DOCX':return StreamingResponse(io.BytesIO(data),media_type=DOCX_MIME,headers={'Content-Disposition':f'attachment; filename="{ses_filename(info,".docx")}"'})
 pdf=ses_pdf([data])[0]
 return StreamingResponse(io.BytesIO(pdf),media_type='application/pdf',headers={'Content-Disposition':f'{"attachment" if download else "inline"}; filename="{ses_filename(info,".pdf")}"'})

@app.get('/api/sk/ses')
def sk_ses_list(request:Request,q:str='',province:str='',status:str='',review:str='',jenis:str='',page:int=1,limit:int=20):
 u=user(request,allowed=SES_SK_VIEWERS);page=max(1,page);limit=min(max(limit,1),100)
 roles=(ses_role_arg(jenis),) if jenis else sk_ses.ROLES
 with db() as c:
  data=rows(c,SES_JOIN.replace('a.prov_code,','a.prov_code,a.sk_no wib_sk_no,a.status wib_status,')+f""" WHERE s.ses_role IN ({','.join('?'*len(roles))})
    ORDER BY s.review_status IN ('menunggu_ses','menunggu_pengesahan') DESC,s.status='active' DESC,s.submitted_at DESC,s.id DESC""",roles)
  counts={k:0 for k in SES_STEPS};per_role={r:0 for r in sk_ses.ROLES}
  for x in data:counts[x['review_status']]=counts.get(x['review_status'],0)+1;per_role[x['ses_role']]+=1
  items=[]
  for s in data:
   if u['role']=='dpw' and s['province']!=u['region']:continue
   if status in ('draft','active','inactive') and s['status']!=status:continue
   if review and s['review_status']!=review:continue
   info=ses_info(c,s)
   if province and not (info['prov'] and info['prov']['kode']==province):continue
   if q and q.lower() not in ' '.join([s['full_name'],info['nomor'],info['wilayah'] or '']).lower():continue
   items.append({'id':s['id'],'full_name':s['full_name'],'jenis':s['ses_role'],'wib':f"{s['title']} {s['level']}",'status':s['status'],'nomor':info['nomor'],'problem':info['problem'],
    'wilayah':info['wilayah'],'provinsi':info['prov']['nama'] if info['prov'] else s['province'],'kode':info['kode'],'started_at':s['started_at'],
    'review_status':s['review_status'],'review_label':SES_STEPS.get(s['review_status'],s['review_status']),'review_note':s['review_note'],'submitted_at':s['submitted_at'],'person_id':s['person_id'],'wib_sk':s['wib_sk_no'],'wib_status':s['wib_status'],'replace_holder':s['replace_holder']=='1'})
 total=len(items);templates={r:p.exists() for r,p in SES_TEMPLATES.items()}
 return {'items':items[(page-1)*limit:page*limit],'total':total,'page':page,'pages':math.ceil(total/limit),'provinces':[{'kode':x['kode'],'nama':x['nama']} for x in sk_ses.REF['provinsi']],
  'can_edit':u['role'] in SES_SK_EDITORS,'can_submit':u['role'] in SES_SUBMITTERS,'can_check':u['role'] in SES_CHECKERS,'can_ratify':u['role'] in SES_RATIFIERS,
  'counts':counts,'per_role':per_role,'roles':list(sk_ses.ROLES),'steps':SES_STEPS,'templates':templates,'has_template':templates[sk_ses.ROLE],'word':docx_sk.word_available()}

@app.get('/api/sk/ses/reference')
def sk_ses_reference(request:Request,jenis:str=''):
 """Daftar provinsi & kab/kota SES dengan pemegang aktif dan jumlah Ketua WIB aktif (calon) untuk satu jenis SK."""
 user(request,allowed=SES_SUBMITTERS);role=ses_role_arg(jenis)
 with db() as c:holders=ses_holders(c);calon=ses_ketua(c,role)
 who=lambda h:{'full_name':h['full_name'],'sk_no':h['sk_no']} if h else None
 n_prov,n_reg={},{}
 for a,sp,sw in calon:
  n_prov[sp['kode']]=n_prov.get(sp['kode'],0)+1
  if sw:n_reg[(sp['kode'],sw['kode'])]=n_reg.get((sp['kode'],sw['kode']),0)+1
 units={}
 for k,h in holders.items():
  if k[0]==sk_ses.ROLE_UNIT:units[(k[1],k[2])]=units.get((k[1],k[2]),0)+1
 return {'jenis':role,'provinsi':[{'kode':p['kode'],'nama':p['nama'],'calon':n_prov.get(p['kode'],0),'holder':who(holders.get((sk_ses.ROLE_WIL,p['kode']))),
  'wilayah':[{'kode':w['kode'],'nama':w['tampil'],'calon':n_reg.get((p['kode'],w['kode']),0),'holder':who(holders.get((sk_ses.ROLE,p['kode'],w['kode']))),'units':units.get((p['kode'],w['kode']),0)} for w in p['wilayah']]}
  for p in sk_ses.REF['provinsi']]}

@app.get('/api/sk/ses/candidates')
def sk_ses_candidates(request:Request,prov:str,kode:str='',jenis:str=''):
 """Ketua WIB aktif di provinsi (Koordinator Wilayah) atau kab/kota (Kepala Cabang/Unit), beserta unit yang sudah terisi."""
 user(request,allowed=SES_SUBMITTERS);role=ses_role_arg(jenis)
 with db() as c:
  out=[]
  for a,sp,sw in ses_ketua(c,role):
   if sp['kode']!=prov or (role!=sk_ses.ROLE_WIL and sw['kode']!=kode):continue
   s=row(c,'SELECT status,review_status,ses_unit_code FROM ses_assignments WHERE wib_appointment_id=?',(a['id'],))
   out.append({'appointment_id':a['id'],'full_name':a['full_name'],'title':a['title'],'level':a['level'],'district':a['district'],'sk_no':a['sk_no'],
    'ses_status':s['status'] if s else None,'review_status':s['review_status'] if s else None,'unit':s['ses_unit_code'] if s else None})
  units=sorted([{'unit':k[3],'full_name':h['full_name'],'wilayah':h['region'],'sk_no':h['sk_no']} for k,h in ses_holders(c).items() if k[0]==sk_ses.ROLE_UNIT and k[1]==prov and k[2]==kode],key=lambda x:x['unit'])
 return {'items':out,'units':units if role==sk_ses.ROLE_UNIT else []}

class NewSES(BaseModel):
 appointment_id:int;tanggal:str='';replace:bool=False;note:str='';unit:str=''
def ses_plan(c,v):
 try:when=datetime.strptime(v.tanggal,'%Y-%m-%d').date() if v.tanggal else datetime.now(TZ).date()
 except ValueError:raise HTTPException(422,'Tanggal SK tidak valid')
 a=row(c,'SELECT a.*,p.full_name,p.gender FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.id=?',(v.appointment_id,))
 if not a or a['status']!='active':raise HTTPException(409,'Penerima SK SES harus pengurus WIB aktif')
 role=sk_ses.LEVEL_ROLE.get(a['level'])
 if not role or a['title'].strip().lower()!='ketua':raise HTTPException(409,'SK SES hanya untuk Ketua: Ketua DPW → Koordinator Wilayah, Ketua DPD/DPC → Kepala Cabang, Ketua PAC → Kepala Unit')
 unit=None
 if role==sk_ses.ROLE_UNIT:
  unit=sk_ses.unit_code(v.unit)
  if not unit:raise HTTPException(422,'Isi nomor unit dengan angka (mis. 1 atau 01)')
 sp,sw=sk_ses.resolve(a);wilayah,key,problem=ses_place(role,a,sp,sw,unit)
 if problem:raise HTTPException(409,problem)
 holder=ses_holders(c).get(key)
 if holder and holder['person_id']==a['person_id']:raise HTTPException(409,f"{a['full_name']} sudah menjadi {role} aktif {wilayah} ({holder['sk_no']})")
 return a,role,sp,sw,unit,wilayah,when,holder
@app.post('/api/sk/ses/new/preview')
def sk_ses_preview(v:NewSES,request:Request):
 user(request,True,SES_SUBMITTERS)
 with db() as c:a,role,sp,sw,unit,wilayah,when,holder=ses_plan(c,v)
 return {'jenis':role,'nomor':sk_ses.number(role,sp,sw,when,unit),'wilayah':wilayah,'provinsi':sp['nama'],'nama':a['full_name'],'tanggal':sk_wib.tanggal_teks(when),
  'holder':{'full_name':holder['full_name'],'sk_no':holder['sk_no']} if holder else None}
@app.post('/api/sk/ses/new')
def sk_ses_new(v:NewSES,request:Request):
 """Jovi/Febri mengajukan SK SES. Pengajuan masuk ke antrean Petugas SES (Ihsan); SK baru terbit
 setelah disetujui Petugas SES dan disahkan Direksi SES Group."""
 u=user(request,True,SES_SUBMITTERS)
 with transaction() as c:
  a,role,sp,sw,unit,wilayah,when,holder=ses_plan(c,v)
  if holder and not v.replace:raise HTTPException(409,f"{wilayah} masih memiliki {role} aktif ({holder['full_name']}). Centang penggantian bila pengajuan ini untuk menggantikannya.")
  s=row(c,'SELECT * FROM ses_assignments WHERE wib_appointment_id=?',(a['id'],))
  if s and s['review_status'] in ('menunggu_ses','menunggu_pengesahan'):raise HTTPException(409,'Pengajuan SK SES untuk pengurus ini sedang diproses')
  if s and s['status']=='active':raise HTTPException(409,'Pengurus ini sudah memiliki SK SES aktif')
  rep='1' if v.replace and holder else '0';city=sw['kode'] if sw else None
  if s:
   sid=s['id'];frm=s['review_status']
   c.execute("UPDATE ses_assignments SET ses_role=?,ses_prov_code=?,ses_city_code=?,ses_unit_code=?,region=?,status='draft',review_status='menunggu_ses',review_note=NULL,submitted_by=?,submitted_at=?,replace_holder=? WHERE id=?",
    (role,sp['kode'],city,unit,wilayah,u['id'],now(),rep,sid))
  else:
   frm='draft'
   c.execute("INSERT INTO ses_assignments(person_id,wib_appointment_id,ses_role,region,status,created_at,ses_prov_code,ses_city_code,ses_unit_code,review_status,submitted_by,submitted_at,replace_holder) VALUES(?,?,?,?,'draft',?,?,?,?,'menunggu_ses',?,?,?)",
    (a['person_id'],a['id'],role,wilayah,now(),sp['kode'],city,unit,u['id'],now(),rep))
   sid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
  ses_log(c,u,sid,'diajukan',frm,'menunggu_ses',v.note or (f'Pengajuan penggantian {role}' if rep=='1' else f'Pengajuan SK SES {role}'))
  audit(c,u['id'],'submit_ses','ses_assignment',sid,f'{role} {wilayah}')
 return {'ok':True,'id':sid,'review_status':'menunggu_ses','full_name':a['full_name'],'wilayah':wilayah,'jenis':role}

@app.post('/api/ses/{id}/submit')
def ses_submit(id:int,request:Request,v:Optional[SesApprove]=None):
 """Ajukan (ulang) draft atau pengajuan yang diminta diperbaiki."""
 u=user(request,True,SES_SUBMITTERS)
 with transaction() as c:
  s=row(c,'SELECT * FROM ses_assignments WHERE id=?',(id,))
  if not s:raise HTTPException(404,'Pengajuan tidak ditemukan')
  if s['review_status'] not in ('draft','perlu_perbaikan','ditolak'):raise HTTPException(409,f"Pengajuan berstatus {SES_STEPS.get(s['review_status'])}")
  a=row(c,'SELECT * FROM appointments WHERE id=?',(s['wib_appointment_id'],))
  if not a or a['status']!='active':raise HTTPException(409,'SK WIB pengurus ini belum aktif')
  info=ses_info(c,s)
  if info['problem']:raise HTTPException(409,info['problem']+('. Ajukan lewat tombol "Ajukan SK SES" agar nomor unit dapat diisi.' if info['role']==sk_ses.ROLE_UNIT and not info['unit'] else ''))
  c.execute("UPDATE ses_assignments SET ses_prov_code=?,ses_city_code=?,region=?,review_status='menunggu_ses',submitted_by=?,submitted_at=? WHERE id=?",(info['prov']['kode'],info['reg']['kode'] if info['reg'] else None,info['wilayah'],u['id'],now(),id))
  ses_log(c,u,id,'diajukan',s['review_status'],'menunggu_ses',(v.note if v else '') or 'Diajukan ulang')
  audit(c,u['id'],'submit_ses','ses_assignment',id)
 return {'ok':True}

class SesReview(BaseModel):action:str;note:str=''
@app.post('/api/ses/{id}/review')
def ses_review(id:int,v:SesReview,request:Request):
 """Petugas SES memeriksa: setujui (lanjut ke pengesahan Direksi), tolak, atau minta perbaikan. Direksi juga dapat
 menolak atau meminta perbaikan pada tahap pengesahan."""
 u=user(request,True,list(dict.fromkeys(SES_CHECKERS+SES_RATIFIERS)))
 if v.action not in ('setujui','tolak','perbaikan'):raise HTTPException(422,'Tindakan tidak dikenal')
 if v.action!='setujui' and len(v.note.strip())<5:raise HTTPException(422,'Tuliskan alasan penolakan atau perbaikan (minimal 5 huruf)')
 with transaction() as c:
  s=row(c,'SELECT * FROM ses_assignments WHERE id=?',(id,))
  if not s:raise HTTPException(404,'Pengajuan tidak ditemukan')
  st=s['review_status']
  if st=='menunggu_ses':
   if u['role'] not in SES_CHECKERS:raise HTTPException(403,'Pemeriksaan tahap ini dilakukan Petugas SES Group')
  elif st=='menunggu_pengesahan':
   if u['role'] not in SES_RATIFIERS:raise HTTPException(403,'Tahap ini menunggu pengesahan Direksi SES Group')
   if v.action=='setujui':raise HTTPException(409,'Gunakan tombol Sahkan untuk menerbitkan SK')
  else:raise HTTPException(409,f"Pengajuan berstatus {SES_STEPS.get(st,st)}; tidak ada pemeriksaan yang menunggu")
  to={'setujui':'menunggu_pengesahan','tolak':'ditolak','perbaikan':'perlu_perbaikan'}[v.action]
  if v.action=='setujui':
   a=row(c,'SELECT status FROM appointments WHERE id=?',(s['wib_appointment_id'],))
   if not a or a['status']!='active':raise HTTPException(409,'SK WIB pengurus ini belum aktif')
  c.execute('UPDATE ses_assignments SET review_status=?,review_note=? WHERE id=?',(to,v.note.strip()[:1000] or None,id))
  ses_log(c,u,id,{'setujui':'disetujui_petugas','tolak':'ditolak','perbaikan':'perlu_perbaikan'}[v.action],st,to,v.note)
  audit(c,u['id'],'review_ses','ses_assignment',id,f'{st}->{to}')
 return {'ok':True,'review_status':to}

@app.get('/api/ses/{id}/timeline')
def ses_timeline(id:int,request:Request):
 u=user(request,allowed=SES_SK_VIEWERS)
 with db() as c:
  s=row(c,'''SELECT s.*,p.full_name,p.gender,p.phone,p.nik_last4,a.title,a.level,a.province,a.city,a.sk_no wib_sk_no,a.status wib_status,a.started_at wib_started FROM ses_assignments s
   JOIN people p ON p.id=s.person_id JOIN appointments a ON a.id=s.wib_appointment_id WHERE s.id=?''',(id,))
  if not s:raise HTTPException(404,'Pengajuan tidak ditemukan')
  if u['role']=='dpw' and s['province']!=u['region']:raise HTTPException(403,'Di luar wilayah')
  info=ses_info(c,s)
  docs=rows(c,"SELECT id,doc_type,original_name,status,uploaded_at FROM documents WHERE target_kind='person' AND target_id=? ORDER BY id DESC",(s['person_id'],))
  log=rows(c,'SELECT * FROM ses_reviews WHERE assignment_id=? ORDER BY id',(id,))
  holder=ses_holders(c).get(info['key']) if info['key'] else None
 if u['role'] in ('ses_admin','ses_pic','ses_director','auditor'):s['phone']=mask_phone(s['phone'])
 return {'item':{k:s[k] for k in ('id','full_name','gender','phone','nik_last4','title','level','province','city','wib_sk_no','wib_status','wib_started','status','review_status','review_note','sk_no','started_at','submitted_at','person_id','ses_role')},
  'review_label':SES_STEPS.get(s['review_status']),'nomor':info['nomor'],'wilayah':info['wilayah'],'kode':info['kode'],'problem':info['problem'],
  'holder':{'full_name':holder['full_name'],'sk_no':holder['sk_no']} if holder and holder['person_id']!=s['person_id'] else None,'replace_holder':s['replace_holder']=='1',
  'docs':docs,'log':log,'steps':SES_STEPS}

@app.post('/api/sk/ses/import')
async def sk_ses_import(request:Request,file:UploadFile=File(...)):
 """Impor Kepala Cabang dari Table Wilayah SES Group.xlsx (kolom NAMA). Setiap nama dicocokkan dengan pengurus
 WIB aktif DPD/DPC di kab/kota yang sama. Yang cocok dan kolom TANGGAL-nya terisi langsung mendapat SK SES aktif;
 tanpa TANGGAL masuk draft."""
 u=user(request,True,SES_SK_EDITORS)
 data=await file.read(10*1024*1024+1)
 if len(data)>10*1024*1024:raise HTTPException(413,'File maksimum 10 MB')
 try:records=sk_ses.read_table(data)
 except Exception:raise HTTPException(422,'File bukan Excel .xlsx yang valid')
 if records is None:raise HTTPException(422,'Sheet "KAB KOTA" dengan kolom No Wilayah, No Daerah, dan NAMA tidak ditemukan')
 return await run_in_threadpool(import_ses,records,u['id'])
def import_ses(records,actor_id):
 res={'ok':True,'active':0,'draft':0,'updated':0,'already':0,'unmatched':[],'skipped':[],'drafts':[]}
 with transaction() as c:
  holders=ses_holders(c);calon=ses_wib_pengurus(c,True)
  for d in records:
   sp=sk_ses.province(d['prov']);sw=sk_ses.region(sp,d['kode'])
   if not sw:res['skipped'].append([d['_row'],d['nama'],f"Kode {d['prov']}-{d['kode']} tidak ada di daftar wilayah SES"]);continue
   key=(sp['kode'],sw['kode']);hkey=(sk_ses.ROLE,*key);people=calon.get(key,[]);k=sk_ses.name_key(d['nama'])
   found=[a for a in people if sk_ses.name_key(a['full_name'])==k] or [a for a in people if len(k)>=6 and (k in sk_ses.name_key(a['full_name']) or sk_ses.name_key(a['full_name']) in k)]
   found.sort(key=lambda a:sk_wib.JABATAN_KODE.get(a['title'].lower(),'99'))
   if not found:
    res['unmatched'].append([d['_row'],d['nama'],sw['tampil'],'Belum ada pengurus WIB di wilayah ini' if not people else 'Nama tidak cocok dengan pengurus WIB di wilayah ini: '+', '.join(f"{a['full_name']} ({a['title']})" for a in people[:6])]);continue
   a=found[0];h=holders.get(hkey);when=d['tanggal'];given=d['nomor']
   if h and h['person_id']!=a['person_id']:res['skipped'].append([d['_row'],d['nama'],f"{sw['tampil']} sudah memiliki Kepala Cabang aktif ({h['full_name']})"]);continue
   s=row(c,'SELECT * FROM ses_assignments WHERE wib_appointment_id=?',(a['id'],))
   if s:sid=s['id'];c.execute('UPDATE ses_assignments SET ses_role=?,ses_prov_code=?,ses_city_code=?,region=? WHERE id=?',(sk_ses.ROLE,sp['kode'],sw['kode'],sw['tampil'],sid))
   else:
    c.execute('INSERT INTO ses_assignments(person_id,wib_appointment_id,ses_role,region,status,created_at,ses_prov_code,ses_city_code) VALUES(?,?,?,?,?,?,?,?)',(a['person_id'],a['id'],sk_ses.ROLE,sw['tampil'],'draft',now(),sp['kode'],sw['kode']))
    sid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
   if not when or a['status']!='active':
    if s and s['status']=='active':res['already']+=1;continue
    why=('SK WIB orang ini belum aktif (isi TANGGAL di Data_SK_WIB lalu impor dulu)' if a['status']!='active' else '')+('; ' if a['status']!='active' and not when else '')+('' if when else f"TANGGAL '{d['tanggal_teks']}' tidak terbaca" if d['tanggal_teks'] else 'TANGGAL belum diisi')
    res['draft']+=1;res['drafts'].append([d['_row'],d['nama'],f"{sw['tampil']}: {why}"]);continue
   skno=given or sk_ses.number(sk_ses.ROLE,sp,sw,when)
   if s and s['status']=='active' and s['started_at']==when.isoformat() and s['sk_no']==skno:res['already']+=1;continue
   issue_ses_sk(c,sid,sk_ses.ROLE,sp,sw,None,sw['tampil'],when,given or None);holders[hkey]={**a,'person_id':a['person_id'],'full_name':a['full_name'],'sk_no':skno}
   c.execute("UPDATE ses_assignments SET review_status='sk_diterbitkan' WHERE id=?",(sid,))
   ses_log(c,{'id':actor_id,'full_name':'Impor arsip','role':None},sid,'impor_arsip',s['review_status'] if s else 'draft','sk_diterbitkan',f'SK lama {skno} tertanggal {when.isoformat()} dicatat dari Excel')
   res['updated' if s and s['status']=='active' else 'active']+=1
  audit(c,actor_id,'import_ses','ses_assignment',0,f"{res['active']} SK SES aktif, {res['updated']} diperbarui, {res['draft']} draft, {len(res['unmatched'])} tidak cocok, {len(res['skipped'])} dilewati")
 res['message']=(f"{res['active']} Kepala Cabang mendapat SK SES aktif sesuai kolom TANGGAL; {res['draft']} masuk draft (TANGGAL belum diisi atau SK WIB-nya belum aktif). "
  f"{len(res['unmatched'])} nama belum cocok dengan pengurus WIB dan perlu dicek."+(f" {res['updated']} SK diperbarui tanggal/nomornya." if res['updated'] else ''))
 return res

@app.get('/api/sk/ses/zip')
def sk_ses_zip(request:Request,ids:str='',province:str='',jenis:str=''):
 """ZIP SK SES (Word + PDF): daftar id tertentu, atau semua SK SES aktif (opsional per jenis dan per provinsi SES)."""
 u=user(request,allowed=SES_SK_EDITORS+['ses_admin'])
 roles=(ses_role_arg(jenis),) if jenis else sk_ses.ROLES
 with db() as c:
  if ids:
   want=[int(x) for x in ids.split(',') if x.strip().isdigit()][:600]
   data=[r for r in (row(c,'SELECT * FROM ses_assignments WHERE id=?',(i,)) for i in want) if r and r['ses_role'] in roles]
  else:data=rows(c,f"SELECT * FROM ses_assignments WHERE status='active' AND ses_role IN ({','.join('?'*len(roles))}) ORDER BY ses_prov_code,ses_role,ses_city_code,ses_unit_code",roles)
  docs=[]
  for s in data:
   info=ses_info(c,s)
   if info['problem'] or (province and info['prov']['kode']!=province) or not SES_TEMPLATES[info['role']].exists():continue
   docs.append((ses_fill(SES_TEMPLATES[info['role']].read_bytes(),info),info))
 if not docs:raise HTTPException(404,'Tidak ada SK SES untuk diunduh')
 pdfs=ses_pdf([d for d,_ in docs])
 out=tempfile.SpooledTemporaryFile(max_size=50*1024*1024)
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for (d,info),pdf in zip(docs,pdfs):
   folder=re.sub(r'[^A-Za-z0-9]+','_',f"{info['prov']['kode']}_{info['prov']['nama']}").strip('_')
   z.writestr(f'{folder}/{ses_filename(info,".docx")}',d);z.writestr(f'{folder}/{ses_filename(info,".pdf")}',pdf)
 out.seek(0)
 name='SK_SES_'+re.sub(r'\W+','_',roles[0])+'.zip' if len(roles)==1 else 'SK_SES_Group.zip'
 return StreamingResponse(out,media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="{name}"'})

@app.get('/api/sk/ses/template')
def sk_ses_template_get(request:Request,jenis:str=''):
 user(request,allowed=SES_SK_EDITORS+['ses_admin']);role=ses_role_arg(jenis)
 return FileResponse(ses_template(role),media_type=DOCX_MIME,filename=f"Template_SK_SES_{role.replace(' ','_')}.docx")
@app.post('/api/sk/ses/template')
async def sk_ses_template_upload(request:Request,file:UploadFile=File(...),jenis:str=Form('')):
 u=user(request,True,SES_SK_EDITORS);role=ses_role_arg(jenis)
 data=await file.read(10*1024*1024+1)
 if len(data)>10*1024*1024 or not data.startswith(b'PK'):raise HTTPException(422,'Unggah berkas Word .docx (maksimum 10 MB)')
 try:data=docx_sk.normalize_ses_template(data);fields=docx_sk.template_fields(data)
 except Exception:raise HTTPException(422,'Berkas bukan dokumen Word .docx yang valid')
 missing=sorted(sk_ses.FIELDS_REQUIRED-fields)
 if missing:raise HTTPException(422,'Template harus memuat merge field: '+', '.join('«'+f+'»' for f in missing))
 SES_TEMPLATES[role].write_bytes(data)
 with transaction() as c:audit(c,u['id'],'upload_ses_docx','sk_template',0,f'Template Word SK SES {role} diganti: '+', '.join(sorted(fields)))
 docx_sk.warm_up()
 return {'ok':True,'fields':sorted(fields),'jenis':role}

@app.on_event('startup')
def warm_word():
 if any(p.exists() for p in SES_TEMPLATES.values()):docx_sk.warm_up()

@app.get('/api/sk/bulk')
def sk_bulk(request:Request,province:str='',level:str='',draft:str='',title:str=''):
 """ZIP semua SK WIB yang sudah terbit (aktif), opsional per provinsi (kode), jenjang, dan jabatan.
 title: daftar jabatan dipisah koma (Ketua,Sekretaris,Bendahara); kosong = semua jabatan.
 draft=1: sertakan juga SK draft (belum disahkan) dengan nomor bertanda (DRAFT); data tidak diubah."""
 u=user(request,allowed=SK_EDITORS)
 if level and level not in ORGS:raise HTTPException(422,'Jenjang tidak dikenal')
 titles=sorted({t.strip().lower() for t in title.split(',') if t.strip()})
 with_draft=draft.lower() in ('1','on','true','ya')
 status_sql="((a.status='active' AND a.sk_no IS NOT NULL) OR a.status='draft')" if with_draft else "a.status='active' AND a.sk_no IS NOT NULL"
 where=status_sql;params=[]
 if level:where+=' AND a.level=?';params.append(level)
 if titles:where+=' AND lower(trim(a.title)) IN ('+','.join('?'*len(titles))+')';params+=titles
 items=[]
 with db() as c:
  tpl=sk_template(c)
  data=rows(c,"SELECT a.*,p.full_name,p.gender,p.phone FROM appointments a JOIN people p ON p.id=a.person_id WHERE "+where+' ORDER BY a.prov_code,a.level,a.city_code,a.district,a.id',tuple(params))
  for a in data:
   info,prov,reg=sk_info(c,a)
   if province and (not prov or prov['kode']!=province):continue
   folder=f"{prov['kode']} {prov['nama']}" if prov else a['province'].upper()
   items.append({'folder':folder,'name':sk_filename(a,info,''),'info':info,
    'row':[prov['nama'] if prov else a['province'],a['level'],info['wilayah_judul'],info['jabatan'],info['nama'],'P' if info['sapaan']=='Sdri.' else ('L' if a['gender'] else ''),a['phone'] or '',info['nomor'],info['tanggal']]})
 if not items:raise HTTPException(404,'Belum ada SK untuk filter ini')
 per={}
 for x in items:per[x['row'][1]]=per.get(x['row'][1],0)+1
 pname=(sk_wib.province_by_code(province) or {}).get('nama',province) if province else 'semua'
 jname=', '.join(t.capitalize() for t in titles) or 'semua'
 report=[f'DAFTAR SK WIB - diunduh {tanggal_id()} oleh {u["full_name"]}',f"Filter: provinsi={pname}, jenjang={level or 'semua'}, jabatan={jname}",f'Jumlah SK: {len(items)} ('+', '.join(f'{k} {v}' for k,v in sorted(per.items()))+')',
  (f"Termasuk {sum(x['info']['draft'] for x in items)} SK DRAFT (belum disahkan; nomor bertanda DRAFT, bukan nomor resmi)." if with_draft else 'Hanya SK yang sudah terbit (status aktif). Jabatan draft tidak termasuk.')]
 out=tempfile.TemporaryFile()
 with db() as c:images=sk_images(c)
 sk_wib.bulk_zip(out,items,tpl,images,report)
 with transaction() as c:audit(c,u['id'],'download_sk_bulk','sk',0,f'{len(items)} SK, provinsi={pname}, jenjang={level or "semua"}, jabatan={jname}')
 size=out.tell();out.seek(0)
 def stream():
  try:
   while chunk:=out.read(1024*1024):yield chunk
  finally:out.close()
 name=f"SK_WIB_{today()}"+('_termasuk_draft' if with_draft else '')+(f"_{province}_{re.sub(r'[^A-Za-z0-9]+','_',pname)}" if province else '')+(f'_{level}' if level else '')+(''.join('_'+t.capitalize() for t in titles) if titles else '')+'.zip'
 return StreamingResponse(stream(),media_type='application/zip',headers={'Content-Disposition':f'attachment; filename="{name}"','Content-Length':str(size),'X-SK-Summary':safe_json({'dibuat':len(items),'per_jenjang':per})})
def tanggal_id():return sk_wib.tanggal_teks(datetime.now(TZ).date())

@app.get('/api/health')
def health():return {'status':'ok','mode':'demo' if os.environ.get('WIB_SEED_DEMO')=='1' else 'operasional_lokal'}


class PasswordChange(BaseModel):
 old_password:str=Field(min_length=1)
 new_password:str=Field(min_length=12,max_length=128)
@app.post('/api/account/password')
def change_password(v:PasswordChange,request:Request):
 u=user(request,True)
 if not (re.search(r'[A-Za-z]',v.new_password) and re.search(r'[0-9]',v.new_password)):
  raise HTTPException(422,'Kata sandi baru harus mengandung huruf dan angka')
 with transaction() as c:
  record=row(c,'SELECT password_hash FROM users WHERE id=?',(u['id'],))
  if not record or not checkpass(v.old_password,record['password_hash']):raise HTTPException(403,'Kata sandi lama tidak sesuai')
  c.execute('UPDATE users SET password_hash=? WHERE id=?',(hashpass(v.new_password),u['id']))
  c.execute('DELETE FROM sessions WHERE user_id=? AND token_hash<>?',(u['id'],hashlib.sha256(request.cookies['wib_session'].encode()).hexdigest()))
  audit(c,u['id'],'change_password','user',u['id'])
 return {'ok':True}

class NewUser(BaseModel):
 username:str=Field(min_length=3,max_length=40)
 full_name:str=Field(min_length=3,max_length=160)
 role:str
 region:str=''
 password:str=Field(min_length=12,max_length=128)
 appointment_id:Optional[int]=None
 report_access:bool=False
@app.get('/api/users')
def list_users(request:Request):
 u=user(request,allowed=['superadmin'])
 with db() as c:return {'items':rows(c,'''SELECT u.id,u.username,u.role,u.full_name,u.region,u.active,u.appointment_id,u.report_access,a.title,a.level,a.province,a.city,a.district,a.status appointment_status
   FROM users u LEFT JOIN appointments a ON a.id=u.appointment_id ORDER BY u.id''')}
@app.post('/api/users')
def create_user(v:NewUser,request:Request):
 u=user(request,True,['superadmin'])
 if v.role not in ROLES:raise HTTPException(422,'Peran tidak dikenal')
 if not re.fullmatch('[a-z0-9_.-]+',v.username):raise HTTPException(422,'Username hanya huruf kecil, angka, titik, dan garis')
 if not (re.search(r'[A-Za-z]',v.password) and re.search(r'[0-9]',v.password)):raise HTTPException(422,'Kata sandi harus memuat huruf dan angka')
 if v.role=='dpw' and not v.region.strip():raise HTTPException(422,'Wilayah wajib diisi untuk DPW')
 if v.role=='pengurus' and not v.appointment_id:raise HTTPException(422,'Pilih jabatan pengurus (Ketua/Sekretaris) yang memakai akun ini')
 with transaction() as c:
  if row(c,'SELECT id FROM users WHERE username=? COLLATE NOCASE',(v.username,)):raise HTTPException(409,'Username sudah digunakan')
  if v.role=='pengurus':
   a=row(c,'SELECT * FROM appointments WHERE id=?',(v.appointment_id,))
   if not a or a['title'].lower() not in ('ketua','sekretaris'):raise HTTPException(422,'Akun pengurus wilayah hanya untuk Ketua atau Sekretaris')
  c.execute('INSERT INTO users(username,password_hash,role,full_name,region,appointment_id,report_access) VALUES(?,?,?,?,?,?,?)',(v.username,hashpass(v.password),v.role,v.full_name,v.region.strip() or None,v.appointment_id if v.role=='pengurus' else None,int(v.report_access) if v.role=='pengurus' else 0))
  ident=c.execute('SELECT last_insert_rowid()').fetchone()[0]
  audit(c,u['id'],'create_user','user',ident)
 return {'ok':True,'id':ident}

class UserToggle(BaseModel):active:bool
@app.post('/api/users/{id}/active')
def user_toggle(id:int,v:UserToggle,request:Request):
 u=user(request,True,['superadmin'])
 if id==u['id'] and not v.active:raise HTTPException(409,'Tidak dapat menonaktifkan akun sendiri')
 with transaction() as c:
  if not row(c,'SELECT id FROM users WHERE id=?',(id,)):raise HTTPException(404,'Pengguna tidak ditemukan')
  c.execute('UPDATE users SET active=? WHERE id=?',(int(v.active),id))
  if not v.active:c.execute('DELETE FROM sessions WHERE user_id=?',(id,))
  audit(c,u['id'],'set_user_active','user',id,str(v.active))
 return {'ok':True}

@app.get('/api/config')
def get_config(request:Request):
 u=user(request)
 return {'dukcapil':{'status':'belum_terintegrasi','description':'Perlu perjanjian akses resmi. Pemeriksaan lokal hanya validasi format 16 digit.'},'app':'WIB–SES Group','version':'1.1.0','kta_enabled':KTA_ENABLED,'kta_manual':True,'references':{k:(BASE/'assets'/f).exists() for k,f in (('WIB','Profil_WIB_2026.pdf'),('SES','Profil_SES_Group_2026.pdf'))},'organization':'Waktu Indonesia Bergerak','demo':os.environ.get('WIB_SEED_DEMO')=='1'}


@app.get('/api/reference/{org}')
def reference(org:str,request:Request):
 user(request)
 files={'WIB':BASE/'assets'/'Profil_WIB_2026.pdf','SES':BASE/'assets'/'Profil_SES_Group_2026.pdf'}
 if org not in files:raise HTTPException(404,'Profil tidak ditemukan')
 if not files[org].exists():raise HTTPException(404,f'Profil {org} belum diunggah ke folder assets')
 return FileResponse(files[org],media_type='application/pdf',headers={'Content-Disposition':f'inline; filename="Profil_{org}_2026.pdf"'})

class PersonUpdate(BaseModel):
 full_name:str=Field(min_length=3,max_length=160)
 phone:str='';gender:str='';address:str='';nik:str=''
@app.patch('/api/people/{person_id}')
def update_person(person_id:int,v:PersonUpdate,request:Request):
 u=user(request,True,['superadmin','admin_wib','dpw'])
 nik=v.nik.strip()
 if nik and not re.fullmatch(r'\d{16}',nik):raise HTTPException(422,'NIK harus tepat 16 digit angka')
 with transaction() as c:
  old=row(c,'SELECT * FROM people WHERE id=?',(person_id,))
  if not old:raise HTTPException(404,'Anggota tidak ditemukan')
  if u['role']=='dpw' and not row(c,'SELECT id FROM appointments WHERE person_id=? AND province=?',(person_id,u['region'])):raise HTTPException(403,'Bukan wilayah Anda')
  issued=row(c,"SELECT id FROM appointments WHERE person_id=? AND sk_no IS NOT NULL LIMIT 1",(person_id,))
  if issued and old['full_name'].strip().casefold()!=v.full_name.strip().casefold():raise HTTPException(409,'Nama pada SK yang sudah terbit tidak dapat diubah langsung. Gunakan proses koreksi dokumen melalui DPP.')
  nh=nik_hash(nik) if nik else None
  if nh:
   conflict=row(c,'SELECT id FROM people WHERE nik_hash=? AND id<>?',(nh,person_id))
   if conflict:raise HTTPException(409,'NIK telah digunakan oleh anggota lain. Lakukan rekonsiliasi identitas terlebih dahulu.')
  if nik:
   c.execute('UPDATE people SET full_name=?,phone=?,gender=?,address=?,nik_hash=?,nik_encrypted=?,nik_last4=?,nik_status=? WHERE id=?',(v.full_name.strip(),v.phone.strip(),v.gender.strip(),v.address.strip(),nh,CRYPT.encrypt(nik.encode()),nik[-4:],'format_valid_belum_dukcapil',person_id))
  else:
   c.execute('UPDATE people SET full_name=?,phone=?,gender=?,address=? WHERE id=?',(v.full_name.strip(),v.phone.strip(),v.gender.strip(),v.address.strip(),person_id))
  audit(c,u['id'],'update_profile','person',person_id,'Perubahan data profil; NIK tidak ditulis pada log')
 return {'ok':True}

class AppointmentCreate(BaseModel):
 level:str;province:str;city:str='';district:str='';title:str
@app.post('/api/people/{person_id}/appointments')
def add_appointment(person_id:int,v:AppointmentCreate,request:Request):
 u=user(request,True,['superadmin','admin_wib','dpw'])
 if v.level not in ORGS or not v.province.strip() or not v.title.strip():raise HTTPException(422,'Jenjang, wilayah, dan jabatan wajib diisi')
 if not scope(u,v.province):raise HTTPException(403,'Di luar wilayah Anda')
 if v.level in ('DPD','DPC') and not v.city.strip():raise HTTPException(422,'Kabupaten/kota wajib diisi')
 if v.level=='PAC' and not v.district.strip():raise HTTPException(422,'Kecamatan wajib diisi')
 with transaction() as c:
  if not row(c,'SELECT id FROM people WHERE id=?',(person_id,)):raise HTTPException(404,'Data pengurus tidak ditemukan')
  existing=row(c,"SELECT id FROM appointments WHERE person_id=? AND level=? AND province=? AND city=? AND district=? AND title=? AND status IN ('active','draft')",(person_id,v.level,v.province.strip(),v.city.strip(),v.district.strip(),v.title.strip()))
  if existing:raise HTTPException(409,'Jabatan yang sama sudah ada pada data pengurus ini')
  c.execute('INSERT INTO appointments(person_id,level,province,city,district,title,created_at) VALUES(?,?,?,?,?,?,?)',(person_id,v.level,v.province.strip(),v.city.strip(),v.district.strip(),v.title.strip(),now()))
  aid=c.execute('SELECT last_insert_rowid()').fetchone()[0]
  audit(c,u['id'],'add_appointment','appointment',aid,f'person_id={person_id}')
 return {'ok':True,'appointment_id':aid}

# =====================================================================================
# V1.1 · Penugasan & Riwayat WIB
# =====================================================================================
@app.get('/api/history/wib')
def history_wib(request:Request,q:str='',province:str='',level:str='',status:str='',person_id:int=0,page:int=1,limit:int=30):
 """Seluruh riwayat penugasan WIB secara kronologis (terbaru di atas). Jabatan yang berakhir tidak dihapus; satu orang
 dapat memiliki beberapa periode."""
 u=user(request,allowed=['superadmin','admin_wib','ketum','sekjen','waketum','dpw','auditor']);page=max(1,page);limit=min(max(limit,1),100)
 where=["a.status IN ('active','inactive','draft')"];args=[]
 if q:where.append('(p.full_name LIKE ? OR a.city LIKE ? OR a.district LIKE ? OR a.sk_no LIKE ?)');args+=['%'+q+'%']*4
 if province:where.append('a.province=?');args.append(province)
 if level in ORGS:where.append('a.level=?');args.append(level)
 if status in ('active','inactive','draft'):where.append('a.status=?');args.append(status)
 if person_id:where.append('a.person_id=?');args.append(person_id)
 if u['role']=='dpw':where.append('a.province=?');args.append(u['region'])
 filt=' AND '.join(where)
 with db() as c:
  total=row(c,f'SELECT COUNT(*) n FROM appointments a JOIN people p ON p.id=a.person_id WHERE {filt}',args)['n']
  data=rows(c,f'''SELECT a.*,p.full_name,(SELECT COUNT(*) FROM appointments b WHERE b.person_id=a.person_id) n_periode FROM appointments a JOIN people p ON p.id=a.person_id WHERE {filt}
   ORDER BY MAX(COALESCE(a.ended_at,''),COALESCE(a.approved_at,''),COALESCE(a.started_at,''),a.created_at) DESC,a.id DESC LIMIT ? OFFSET ?''',args+[limit,(page-1)*limit])
  for a in data:
   a['docs']=rows(c,"SELECT id,doc_type,original_name FROM documents WHERE target_kind='appointment' AND target_id=? ORDER BY id",(a['id'],))
  provinces=[x['province'] for x in rows(c,'SELECT DISTINCT province FROM appointments ORDER BY province')]
 return {'items':data,'total':total,'page':page,'pages':math.ceil(total/limit),'provinces':provinces,'can_edit':u['role'] in ('superadmin','admin_wib'),'can_end':u['role'] in ('superadmin','ketum')}

class Periode(BaseModel):periode:str
PERIODE_RE=re.compile(r'^(\d{4})\s*[–-]\s*(\d{4})$')
def clean_periode(v):
 m=PERIODE_RE.match(v.strip())
 if not m or not (2000<=int(m[1])<int(m[2])<=2100):raise HTTPException(422,'Periode ditulis seperti 2026–2031')
 return f'{m[1]}–{m[2]}'
@app.post('/api/appointments/{id}/periode')
def set_periode(id:int,v:Periode,request:Request):
 u=user(request,True,['superadmin','admin_wib'])
 per=clean_periode(v.periode)
 with transaction() as c:
  if not row(c,'SELECT id FROM appointments WHERE id=?',(id,)):raise HTTPException(404,'Jabatan tidak ditemukan')
  c.execute('UPDATE appointments SET periode=? WHERE id=?',(per,id));audit(c,u['id'],'set_periode','appointment',id,per)
 return {'ok':True,'periode':per}
@app.post('/api/appointments/{id}/next-period')
def next_period(id:int,v:Periode,request:Request):
 """Tambah periode kepengurusan baru untuk jabatan yang sama. Data periode lama tetap tersimpan; periode baru
 berstatus draft sampai SK-nya disahkan Ketua Umum (saat itu periode lama otomatis berakhir)."""
 u=user(request,True,['superadmin','admin_wib'])
 per=clean_periode(v.periode)
 with transaction() as c:
  a=row(c,'SELECT * FROM appointments WHERE id=?',(id,))
  if not a:raise HTTPException(404,'Jabatan tidak ditemukan')
  if row(c,"SELECT id FROM appointments WHERE person_id=? AND level=? AND province=? AND city=? AND district=? AND title=? AND status='draft'",(a['person_id'],a['level'],a['province'],a['city'],a['district'],a['title'])):
   raise HTTPException(409,'Periode baru untuk jabatan ini sudah dibuat dan masih menunggu SK')
  if row(c,"SELECT id FROM appointments WHERE person_id=? AND level=? AND province=? AND city=? AND district=? AND title=? AND periode=?",(a['person_id'],a['level'],a['province'],a['city'],a['district'],a['title'],per)):
   raise HTTPException(409,f'Periode {per} sudah tercatat untuk jabatan ini')
  c.execute('INSERT INTO appointments(person_id,level,province,city,district,title,status,created_at,prov_code,city_code,sebutan,periode) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
   (a['person_id'],a['level'],a['province'],a['city'],a['district'],a['title'],'draft',now(),a['prov_code'],a['city_code'],a['sebutan'],per))
  nid=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'next_period','appointment',nid,f'dari #{id}: {per}')
 return {'ok':True,'id':nid}

# =====================================================================================
# V1.1 · Laporan Kegiatan wilayah (Ketua DPW/DPD/DPC/PAC)
# =====================================================================================
REPORT_STATUS={'draft':'Draft','diajukan':'Diajukan','diperiksa':'Diperiksa DPP','diterima':'Diterima','perlu_perbaikan':'Perlu Perbaikan'}
REPORT_TYPES=['Rapat & Koordinasi','Sosialisasi','Pelatihan','Bakti Sosial','Pemberdayaan Ekonomi','Kesbangpol & Legalitas','Program Kerja','Kegiatan Lainnya']
REPORT_LEGACY={'menunggu':'diajukan','terverifikasi':'diterima'}
def reporter_seat(c,u):
 """Jabatan aktif yang dipakai akun pengurus untuk melapor; None bila tidak berhak (bukan Ketua aktif, atau
 Sekretaris tanpa hak akses laporan)."""
 if u['role']!='pengurus' or not u.get('appointment_id'):return None
 a=row(c,'SELECT a.*,p.full_name FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.id=?',(u['appointment_id'],))
 if not a or a['status']!='active':return None
 t=a['title'].lower()
 if t=='ketua' or (t=='sekretaris' and u.get('report_access')):return {k:a[k] for k in ('id','person_id','full_name','title','level','province','city','district')}
 return None
def same_region(x,seat):return all((x.get(k) or '')==(seat.get(k) or '') for k in ('level','province','city','district'))
def quarter_of(d):return f'{d[:4]}-Q{(int(d[5:7])-1)//3+1}' if d else ''
def report_row(x):
 x['status']=REPORT_LEGACY.get(x['status'],x['status']);x['status_label']=REPORT_STATUS.get(x['status'],x['status']);x['periode']=quarter_of(x['occurred_at']);return x
def report_access(c,u,x):
 """Hak baca satu laporan."""
 if u['role']=='pengurus':
  seat=reporter_seat(c,u);return bool(seat and same_region(x,seat))
 if u['role']=='dpw':return x.get('province')==u['region']
 return u['role'] in REPORT_MONITORS
def own_report(c,u,id,editable=True):
 x=row(c,"SELECT * FROM activities WHERE id=? AND track='WIB'",(id,))
 if not x:raise HTTPException(404,'Laporan tidak ditemukan')
 seat=reporter_seat(c,u) if u['role']=='pengurus' else None
 if u['role']=='pengurus' and not (seat and same_region(x,seat)):raise HTTPException(403,'Laporan ini bukan milik wilayah Anda')
 if u['role'] not in ('pengurus','superadmin'):raise HTTPException(403,'Laporan dibuat dari akun Ketua wilayah')
 if editable and REPORT_LEGACY.get(x['status'],x['status']) not in ('draft','perlu_perbaikan'):raise HTTPException(409,'Laporan yang sudah diajukan tidak dapat diubah')
 return x

class Report(BaseModel):
 title:str=Field(min_length=3,max_length=200);occurred_at:str;location:str=Field(min_length=2,max_length=200);category:str
 purpose:str='';description:str=Field(min_length=10,max_length=8000);participants:int=Field(ge=0,le=1000000);result:str='';obstacles:str='';followup:str=''
 appointment_id:Optional[int]=None  # hanya superadmin: lapor atas nama jabatan tertentu
def report_values(v):
 try:datetime.strptime(v.occurred_at,'%Y-%m-%d')
 except ValueError:raise HTTPException(422,'Tanggal kegiatan tidak valid')
 if v.category not in REPORT_TYPES:raise HTTPException(422,'Jenis kegiatan tidak dikenal')
 return (v.title.strip(),v.occurred_at,v.location.strip(),v.category,v.purpose.strip()[:4000],v.description.strip(),v.participants,v.result.strip()[:4000],v.obstacles.strip()[:4000],v.followup.strip()[:4000])

@app.get('/api/reports')
def report_list(request:Request,province:str='',city:str='',district:str='',periode:str='',status:str='',level:str='',q:str='',page:int=1,limit:int=20):
 u=user(request);page=max(1,page);limit=min(max(limit,1),100)
 if u['role'] not in REPORT_MONITORS+['pengurus']:raise HTTPException(403,'Laporan kegiatan WIB tidak tersedia untuk peran ini')
 with db() as c:
  seat=reporter_seat(c,u) if u['role']=='pengurus' else None
  if u['role']=='pengurus' and not seat:return {'items':[],'total':0,'page':1,'pages':0,'seat':None,'blocked':'Akun ini belum terhubung ke jabatan Ketua aktif, atau Sekretaris belum diberi hak akses laporan.','types':REPORT_TYPES,'statuses':REPORT_STATUS}
  data=[report_row(x) for x in rows(c,"""SELECT t.id,t.title,t.category,t.occurred_at,t.location,t.participants,t.status,t.level,t.province,t.city,t.district,t.submitted_at,t.reviewed_at,t.review_note,p.full_name,
    (SELECT COUNT(*) FROM activity_files f WHERE f.activity_id=t.id AND f.kind='foto') n_foto,(SELECT COUNT(*) FROM activity_files f WHERE f.activity_id=t.id AND f.kind='pdf') n_pdf
    FROM activities t JOIN people p ON p.id=t.person_id WHERE t.track='WIB' ORDER BY t.occurred_at DESC,t.id DESC""")]
  data=[x for x in data if report_access(c,u,x)]
  if u['role']!='pengurus':data=[x for x in data if x['status']!='draft']  # draft hanya terlihat oleh wilayah pembuat
 f=lambda x:(not province or x['province']==province) and (not city or x['city']==city) and (not district or x['district']==district) and (not periode or x['periode']==periode) \
  and (not status or x['status']==status) and (not level or x['level']==level) and (not q or q.lower() in f"{x['title']} {x['full_name']} {x['location']}".lower())
 out=[x for x in data if f(x)]
 opts={k:sorted({x[k] for x in data if x[k]}) for k in ('province','city','district','periode')}
 counts={k:sum(1 for x in data if x['status']==k) for k in REPORT_STATUS}
 return {'items':out[(page-1)*limit:page*limit],'total':len(out),'page':page,'pages':math.ceil(len(out)/limit),'seat':seat,'options':opts,'counts':counts,'types':REPORT_TYPES,'statuses':REPORT_STATUS,
  'can_create':bool(seat) or u['role']=='superadmin','can_review':u['role'] in REPORT_REVIEWERS}
@app.get('/api/reports/{id}')
def report_get(id:int,request:Request):
 u=user(request)
 with db() as c:
  x=row(c,"SELECT t.*,p.full_name,r.full_name reviewer FROM activities t JOIN people p ON p.id=t.person_id LEFT JOIN users r ON r.id=t.reviewed_by WHERE t.id=? AND t.track='WIB'",(id,))
  if not x or not report_access(c,u,x) or (u['role']!='pengurus' and x['status']=='draft' and u['role']!='superadmin'):raise HTTPException(404,'Laporan tidak ditemukan')
  x['files']=rows(c,'SELECT id,kind,original_name,size,uploaded_at FROM activity_files WHERE activity_id=? ORDER BY id',(id,))
  x['log']=rows(c,"SELECT a.action,a.detail,a.created_at,u.full_name FROM audits a LEFT JOIN users u ON u.id=a.actor WHERE a.entity='report' AND a.entity_id=? ORDER BY a.id",(id,))
  seat=reporter_seat(c,u) if u['role']=='pengurus' else None
 x=report_row(x);x['can_edit']=(bool(seat and same_region(x,seat)) or u['role']=='superadmin') and x['status'] in ('draft','perlu_perbaikan');x['can_review']=u['role'] in REPORT_REVIEWERS and x['status'] in ('diajukan','diperiksa')
 return x
@app.post('/api/reports')
def report_create(v:Report,request:Request):
 u=user(request,True,['pengurus','superadmin'])
 with transaction() as c:
  if u['role']=='pengurus':
   seat=reporter_seat(c,u)
   if not seat:raise HTTPException(403,'Hanya Ketua aktif (atau Sekretaris yang diberi hak) yang dapat membuat laporan')
  else:
   a=row(c,"SELECT * FROM appointments WHERE id=? AND status='active'",(v.appointment_id or 0,))
   if not a:raise HTTPException(422,'Pilih jabatan aktif yang menjadi pelapor')
   seat=a
  c.execute('''INSERT INTO activities(track,person_id,appointment_id,title,occurred_at,location,category,purpose,description,participants,result,obstacles,followup,status,level,province,city,district,created_by,created_at)
   VALUES('WIB',?,?,?,?,?,?,?,?,?,?,?,?,'draft',?,?,?,?,?,?)''',(seat['person_id'],seat['id'],*report_values(v),seat['level'],seat['province'],seat['city'] or '',seat['district'] or '',u['id'],now()))
  rid=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'create','report',rid,'draft')
 return {'ok':True,'id':rid}
@app.patch('/api/reports/{id}')
def report_update(id:int,v:Report,request:Request):
 u=user(request,True,['pengurus','superadmin'])
 with transaction() as c:
  own_report(c,u,id)
  c.execute('UPDATE activities SET title=?,occurred_at=?,location=?,category=?,purpose=?,description=?,participants=?,result=?,obstacles=?,followup=? WHERE id=?',(*report_values(v),id))
  audit(c,u['id'],'update','report',id)
 return {'ok':True}
REPORT_FILE={'.jpg':('foto','image/jpeg',b'\xff\xd8'),'.jpeg':('foto','image/jpeg',b'\xff\xd8'),'.png':('foto','image/png',b'\x89PNG'),'.webp':('foto','image/webp',b'RIFF'),'.pdf':('pdf','application/pdf',b'%PDF-')}
@app.post('/api/reports/{id}/files')
async def report_file(id:int,request:Request,file:UploadFile=File(...)):
 u=user(request,True,['pengurus','superadmin'])
 with db() as c:own_report(c,u,id);n=row(c,'SELECT COUNT(*) n FROM activity_files WHERE activity_id=?',(id,))['n']
 if n>=20:raise HTTPException(409,'Maksimum 20 berkas per laporan')
 ext=Path(file.filename or '').suffix.lower()
 if ext not in REPORT_FILE:raise HTTPException(422,'Unggah foto JPG/PNG/WEBP atau dokumen PDF')
 kind,mime,magic=REPORT_FILE[ext]
 content=await file.read(8*1024*1024+1)
 if len(content)>8*1024*1024:raise HTTPException(413,'Ukuran maksimum 8 MB per berkas')
 if not content.startswith(magic):raise HTTPException(422,'Isi berkas tidak sesuai jenisnya')
 name=secrets.token_hex(18)+ext;(PRIVATE/name).write_bytes(content)
 with transaction() as c:
  c.execute('INSERT INTO activity_files(activity_id,kind,original_name,stored_name,mime,size,uploaded_by,uploaded_at) VALUES(?,?,?,?,?,?,?,?)',(id,kind,Path(file.filename).name[:180],name,mime,len(content),u['id'],now()))
  fid=c.execute('SELECT last_insert_rowid()').fetchone()[0];audit(c,u['id'],'upload','report',id,f'{kind}: {Path(file.filename).name[:80]}')
 return {'ok':True,'id':fid,'kind':kind}
@app.post('/api/reports/files/{fid}/delete')
def report_file_delete(fid:int,request:Request):
 u=user(request,True,['pengurus','superadmin'])
 with transaction() as c:
  f=row(c,'SELECT * FROM activity_files WHERE id=?',(fid,))
  if not f:raise HTTPException(404,'Berkas tidak ditemukan')
  own_report(c,u,f['activity_id'])
  c.execute('DELETE FROM activity_files WHERE id=?',(fid,));audit(c,u['id'],'delete_file','report',f['activity_id'],f['original_name'])
 (PRIVATE/f['stored_name']).unlink(missing_ok=True)
 return {'ok':True}
@app.get('/api/reports/files/{fid}')
def report_file_get(fid:int,request:Request):
 u=user(request)
 with db() as c:
  f=row(c,'SELECT * FROM activity_files WHERE id=?',(fid,))
  x=row(c,'SELECT * FROM activities WHERE id=?',(f['activity_id'],)) if f else None
  if not f or not x or not report_access(c,u,x):raise HTTPException(404,'Berkas tidak ditemukan')
 path=PRIVATE/f['stored_name']
 if not path.exists():raise HTTPException(404,'Berkas tidak tersedia')
 return FileResponse(path,media_type=f['mime'],filename=f['original_name'],content_disposition_type='inline')
@app.post('/api/reports/{id}/submit')
def report_submit(id:int,request:Request):
 u=user(request,True,['pengurus','superadmin'])
 with transaction() as c:
  x=own_report(c,u,id)
  if not row(c,"SELECT id FROM activity_files WHERE activity_id=? AND kind='foto'",(id,)):raise HTTPException(422,'Lampirkan minimal satu foto kegiatan sebelum mengajukan')
  c.execute("UPDATE activities SET status='diajukan',submitted_at=? WHERE id=?",(now(),id));audit(c,u['id'],'submit','report',id,f"{x['status']} -> diajukan")
 return {'ok':True}
class ReportReview(BaseModel):action:str;note:str=''
@app.post('/api/reports/{id}/review')
def report_review(id:int,v:ReportReview,request:Request):
 """Pemeriksaan DPP (Waketum, Sekjen, Ketum): periksa -> diterima / perlu perbaikan."""
 u=user(request,True,REPORT_REVIEWERS)
 if v.action not in ('periksa','terima','perbaikan'):raise HTTPException(422,'Tindakan tidak dikenal')
 if v.action=='perbaikan' and len(v.note.strip())<5:raise HTTPException(422,'Tuliskan catatan perbaikan (minimal 5 huruf)')
 with transaction() as c:
  x=row(c,"SELECT * FROM activities WHERE id=? AND track='WIB'",(id,))
  if not x:raise HTTPException(404,'Laporan tidak ditemukan')
  st=REPORT_LEGACY.get(x['status'],x['status'])
  if st not in ('diajukan','diperiksa'):raise HTTPException(409,f"Laporan berstatus {REPORT_STATUS.get(st,st)}")
  to={'periksa':'diperiksa','terima':'diterima','perbaikan':'perlu_perbaikan'}[v.action]
  c.execute('UPDATE activities SET status=?,reviewed_by=?,reviewed_at=?,review_note=?,verified_at=?,verified_by=? WHERE id=?',(to,u['id'],now(),v.note.strip()[:2000] or x['review_note'],now() if to=='diterima' else None,u['id'] if to=='diterima' else None,id))
  audit(c,u['id'],'review','report',id,f'{st} -> {to}'+(f': {v.note.strip()[:200]}' if v.note.strip() else ''))
 return {'ok':True,'status':to}

def accepted_reports(c):
 """Laporan diterima per (jenjang, provinsi, kab/kota, kecamatan, triwulan)."""
 out={}
 for x in rows(c,"SELECT level,province,city,district,occurred_at FROM activities WHERE track='WIB' AND status IN ('diterima','terverifikasi')"):
  k=(x['level'],x['province'],x['city'] or '',x['district'] or '',quarter_of(x['occurred_at']));out[k]=out.get(k,0)+1
 return out
def current_quarter():d=datetime.now(TZ).date();return f'{d.year}-Q{(d.month-1)//3+1}'
def last_quarters(n=4):
 d=datetime.now(TZ).date();y,q=d.year,(d.month-1)//3+1;out=[]
 for _ in range(n):
  out.append(f'{y}-Q{q}');q-=1
  if q==0:y,q=y-1,4
 return out[::-1]

# =====================================================================================
# V1.1 · Dashboard
# =====================================================================================
@app.get('/api/dashboard/v11')
def dashboard_v11(request:Request):
 u=user(request)
 if u['role']=='pengurus':raise HTTPException(403,'Tidak tersedia')
 ses_only=u['role'] in ('ses_admin','ses_pic','ses_director')
 with db() as c:
  aps=rows(c,'SELECT a.*,p.full_name FROM appointments a JOIN people p ON p.id=a.person_id'+(' WHERE a.province=?' if u['role']=='dpw' else ''),(u['region'],) if u['role']=='dpw' else ())
  act=[a for a in aps if a['status']=='active']
  ses=rows(c,'SELECT s.*,a.province FROM ses_assignments s JOIN appointments a ON a.id=s.wib_appointment_id'+(' WHERE a.province=?' if u['role']=='dpw' else ''),(u['region'],) if u['role']=='dpw' else ())
  reports=[report_row(x) for x in rows(c,"SELECT id,status,occurred_at,level,province,city,district FROM activities WHERE track='WIB'"+(' AND province=?' if u['role']=='dpw' else ''),(u['region'],) if u['role']=='dpw' else ())]
  offices=rows(c,'SELECT * FROM offices'+(' WHERE province=?' if u['role']=='dpw' else ''),(u['region'],) if u['role']=='dpw' else ())
  odocs={}
  for d in rows(c,"SELECT target_id,doc_type FROM documents WHERE target_kind='office' AND status='terverifikasi'"):odocs.setdefault(d['target_id'],set()).add(d['doc_type'])
  acc=accepted_reports(c);quarters=last_quarters(4)
  changes=rows(c,"""SELECT a.action,a.detail,a.created_at,u.full_name actor FROM audits a LEFT JOIN users u ON u.id=a.actor
    WHERE a.action IN ('approve_wib','terminate_wib','approve_ses','terminate_ses','next_period','submit_ses','review_ses','import_data_sk','import_ses') ORDER BY a.id DESC LIMIT 12""")
  ended=rows(c,"SELECT a.id,a.title,a.level,a.province,a.city,a.district,a.ended_at,a.end_reason,a.end_note,p.full_name FROM appointments a JOIN people p ON p.id=a.person_id WHERE a.status='inactive'"+(' AND a.province=?' if u['role']=='dpw' else '')+' ORDER BY a.ended_at DESC LIMIT 10',(u['region'],) if u['role']=='dpw' else ())
 levels={k:sum(1 for a in act if a['level']==k) for k in ORGS}
 byprov={}
 for a in aps:
  b=byprov.setdefault(a['province'],{'province':a['province'],'active':0,'draft':0,'inactive':0,'DPW':0,'DPD':0,'DPC':0,'PAC':0})
  b[a['status'] if a['status'] in ('active','draft','inactive') else 'inactive']+=1
  if a['status']=='active':b[a['level']]+=1
 # keaktifan per triwulan: berapa jabatan aktif (Ketua) yang wilayahnya punya laporan diterima pada triwulan tsb
 ketua=[a for a in act if a['title'].lower()=='ketua']
 key=lambda a,q:(a['level'],a['province'],a['city'] or '',a['district'] or '',q)
 activity=[{'periode':q,'aktif':sum(1 for a in ketua if acc.get(key(a,q))),'laporan':sum(v for k,v in acc.items() if k[4]==q)} for q in quarters]
 cq=current_quarter();prevq=quarters[-2] if len(quarters)>1 else cq
 to_eval=[{'id':a['id'],'full_name':a['full_name'],'title':a['title'],'level':a['level'],'wilayah':a['district'] or a['city'] or a['province'],'province':a['province'],'started_at':a['started_at'],'days':age_days(a['started_at'])}
  for a in ketua if age_days(a['started_at'])>=90 and not acc.get(key(a,cq)) and not acc.get(key(a,prevq))]
 to_eval.sort(key=lambda x:-x['days'])
 ses_counts={k:sum(1 for x in ses if x['review_status']==k) for k in SES_STEPS}
 n_off=len(offices)
 has=lambda o,*ks:all(k in odocs.get(o['id'],set()) for k in ks)
 return {'role':u['role'],'ses_only':ses_only,'demo':os.environ.get('WIB_SEED_DEMO','0')=='1',
  'pengurus':{'total':len(aps),'active':len(act),'inactive':sum(1 for a in aps if a['status']=='inactive'),'draft':sum(1 for a in aps if a['status']=='draft')},
  'levels':levels,'provinces':sorted(byprov.values(),key=lambda x:(-x['active'],x['province'])),
  'sk_wib':{'issued':sum(1 for a in aps if a['sk_no'] and a['status'] in ('active','inactive')),'draft':sum(1 for a in aps if a['status']=='draft')},
  'ses':{'menunggu_ses':ses_counts['menunggu_ses'],'menunggu_pengesahan':ses_counts['menunggu_pengesahan'],'perlu_perbaikan':ses_counts['perlu_perbaikan'],'ditolak':ses_counts['ditolak'],
         'diterbitkan':ses_counts['sk_diterbitkan'],'aktif':sum(1 for x in ses if x['status']=='active')},
  'reports':{k:sum(1 for x in reports if x['status']==k) for k in REPORT_STATUS}|{'triwulan_ini':sum(1 for x in reports if x['periode']==cq and x['status']=='diterima')},
  'activity':activity,'current_quarter':cq,'to_evaluate':[] if ses_only else to_eval[:12],'to_evaluate_total':len(to_eval),
  'kesbangpol':{'offices':n_off,'verified':sum(1 for o in offices if o.get('kesbangpol')=='ada' or has(o,'kesbangpol'))},
  'legal_ses':{'offices':n_off,'akta':sum(1 for o in offices if has(o,'akta_ses_notariil')),'banner':sum(1 for o in offices if has(o,'banner_ses'))},
  'kantor':{'offices':n_off,'alamat':sum(1 for o in offices if (o['address'] or '').strip()),'foto':sum(1 for o in offices if has(o,'foto_depan','foto_dalam'))},
  'changes':[x for x in changes if x['action'] in ('approve_ses','terminate_ses','submit_ses','review_ses','import_ses')] if ses_only else changes,'ended':[] if ses_only else ended}

# Generate KTA (input manual). Nomor KTA adalah kode internal organisasi yang diketik admin; sistem hanya memeriksa format,
# kode jabatan, dan mencegah nomor ganda. Satu nomor hanya boleh dipegang satu kartu aktif; kartu yang dibatalkan tetap
# tersimpan sebagai riwayat dan nomornya dapat diterbitkan ulang untuk pengganti pada jabatan yang sama.
KTA_EDITORS=['superadmin','admin_wib']
KTA_VIEWERS=KTA_EDITORS+['ketum','sekjen','waketum','auditor']
class KtaIn(BaseModel):nomor:str;nama:str;jenis_kelamin:str;jabatan:str;tingkat:str;wilayah:str;provinsi:str='';terbit:str=''
class KtaEdit(BaseModel):nama:str;jenis_kelamin:str;wilayah:str;provinsi:str='';terbit:str=''
class KtaCancel(BaseModel):note:str
def kta_terbit(v):
 v=(v or '').strip()
 if not v:return datetime.now(TZ).date().replace(day=1)
 m=re.fullmatch(r'(\d{4})-(\d{2})(?:-\d{2})?',v)
 if not m or not 1<=int(m[2])<=12:raise HTTPException(422,'Bulan terbit harus berformat YYYY-MM')
 return datetime(int(m[1]),int(m[2]),1).date()
def kta_clean(v,partial=False):
 d={k:' '.join(str(getattr(v,k) or '').split()) for k in ('nomor','nama','jenis_kelamin','jabatan','tingkat','wilayah','provinsi') if hasattr(v,k)}
 for k in ('nama','wilayah'):
  if not d.get(k):raise HTTPException(422,f'{k.title()} wajib diisi')
  if len(d[k])>80:raise HTTPException(422,f'{k.title()} terlalu panjang (maks. 80 huruf)')
 if d.get('jenis_kelamin') not in kta_card.GENDER:raise HTTPException(422,'Jenis kelamin harus Laki-Laki atau Perempuan')
 if not partial:
  if d['jabatan'] not in kta_card.JABATAN:raise HTTPException(422,'Jabatan harus Ketua, Sekretaris, atau Bendahara')
  if d['tingkat'] not in kta_card.TINGKAT:raise HTTPException(422,'Tingkat harus DPW, DPD, DPC, atau PAC')
  p=kta_card.number_problem(d['nomor'],d['tingkat'],d['jabatan'])
  if p:raise HTTPException(422,p)
  kta_master_check(d)
 d['terbit']=kta_terbit(v.terbit);return d
# Daftar induk nomor wilayah (referensi/kta/master_nomor_kta.json, dibangun dari Master_Nomor_KTA_Internal.xlsx).
# Wilayah yang belum terdaftar tetap boleh diketik manual, tetapi nomor induk milik wilayah lain ditolak.
KTA_MASTER=json.loads((BASE/'referensi'/'kta'/'master_nomor_kta.json').read_text(encoding='utf-8'))['wilayah']
KTA_KODE={x['kode']:x for x in KTA_MASTER}
def kta_norm(s):return re.sub(r'^(kabupaten|kab\.?|kota|provinsi|dpw|kecamatan|distrik)\s+','',' '.join(str(s).lower().split()))
def kta_master_check(d):
 base=d['nomor'].rsplit('.',1)[0];e=KTA_KODE.get(base);w=kta_norm(d['wilayah'])
 if e:
  if e['tingkat']!=d['tingkat'] or w not in (kta_norm(e['nama']),kta_norm(e['kartu'])):
   raise HTTPException(422,f"Nomor induk {base} terdaftar untuk {e['tingkat']} {e['kartu']} ({e['provinsi']}), bukan {d['tingkat']} {d['wilayah']}. Pilih wilayah dari daftar induk.")
  if not d.get('provinsi'):d['provinsi']=e['provinsi']
  return
 same=[x for x in KTA_MASTER if x['pp']==base[:2] and x['tingkat']==d['tingkat'] and w in (kta_norm(x['nama']),kta_norm(x['kartu']))]
 if same:raise HTTPException(422,f"{same[0]['tingkat']} {same[0]['kartu']} sudah terdaftar dengan nomor induk {same[0]['kode']}, bukan {base}.")
def kta_card_data(x):return {**x,'terbit':datetime.fromisoformat(x['terbit']).date() if isinstance(x['terbit'],str) else x['terbit']}
def kta_filename(x):return re.sub(r'[\\/:*?"<>|]+',' ',f"KTA WIB {x['jabatan']} {x['tingkat']} {x['wilayah']}".upper()).strip()+'.pdf'
def kta_pdf(cards,name,download=False):
 return StreamingResponse(io.BytesIO(kta_card.render([kta_card_data(x) for x in cards])),media_type='application/pdf',headers={'Content-Disposition':f'{"attachment" if download else "inline"}; filename="{name}"'})
def kta_holder(c,nomor,exclude=0):return row(c,"SELECT id,nama,tingkat,wilayah FROM kta_cards WHERE nomor=? AND status='aktif' AND id<>?",(nomor,exclude))
def kta_where(q,tingkat,status):
 where=['1=1'];args=[]
 if q:where.append('(nama LIKE ? OR nomor LIKE ? OR wilayah LIKE ? OR provinsi LIKE ?)');args+=['%'+q.strip()+'%']*4
 if tingkat in kta_card.TINGKAT:where.append('tingkat=?');args.append(tingkat)
 if status in ('aktif','dibatalkan'):where.append('status=?');args.append(status)
 return ' AND '.join(where),args

@app.get('/api/kta')
def kta_list(request:Request,q:str='',tingkat:str='',status:str='aktif',page:int=1,limit:int=30):
 u=user(request,allowed=KTA_VIEWERS);page=max(1,page);limit=min(max(limit,1),100)
 f,args=kta_where(q,tingkat,status);c=db()
 try:
  total=row(c,f'SELECT COUNT(*) n FROM kta_cards WHERE {f}',args)['n']
  items=rows(c,f'SELECT k.*,u.full_name created_name FROM kta_cards k LEFT JOIN users u ON u.id=k.created_by WHERE {f} ORDER BY k.nomor,k.id DESC LIMIT ? OFFSET ?',args+[limit,(page-1)*limit])
  stats={t:row(c,"SELECT COUNT(*) n FROM kta_cards WHERE status='aktif' AND tingkat=?",(t,))['n'] for t in kta_card.TINGKAT}
  stats['total']=sum(stats.values());stats['dibatalkan']=row(c,"SELECT COUNT(*) n FROM kta_cards WHERE status='dibatalkan'")['n']
  return {'items':items,'total':total,'page':page,'limit':limit,'stats':stats,'can_edit':u['role'] in KTA_EDITORS}
 finally:c.close()

@app.post('/api/kta/preview')
def kta_preview(v:KtaIn,request:Request):
 user(request,True,KTA_EDITORS);d=kta_clean(v);return kta_pdf([d],'PRATINJAU '+kta_filename(d))

@app.post('/api/kta')
def kta_create(v:KtaIn,request:Request):
 u=user(request,True,KTA_EDITORS);d=kta_clean(v)
 with transaction() as c:
  h=kta_holder(c,d['nomor'])
  if h:raise HTTPException(409,f"Nomor {d['nomor']} sudah dipakai kartu aktif atas nama {h['nama']} ({h['tingkat']} {h['wilayah']}). Batalkan kartu itu dahulu bila ada pergantian pengurus.")
  cur=c.execute('INSERT INTO kta_cards(nomor,nama,jenis_kelamin,jabatan,tingkat,wilayah,provinsi,terbit,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(d['nomor'],d['nama'],d['jenis_kelamin'],d['jabatan'],d['tingkat'],d['wilayah'],d['provinsi'],d['terbit'].isoformat(),u['id'],now()))
  audit(c,u['id'],'create_kta','kta',cur.lastrowid,f"{d['nomor']} · {d['jabatan']} {d['tingkat']} {d['wilayah']}")
  return {'ok':True,'id':cur.lastrowid}

@app.patch('/api/kta/{id}')
def kta_edit(id:int,v:KtaEdit,request:Request):
 """Nomor, jabatan, dan tingkat tidak dapat diubah setelah terbit; hanya data penulisan kartu yang dapat dikoreksi."""
 u=user(request,True,KTA_EDITORS);d=kta_clean(v,partial=True);d['terbit']=d['terbit'].isoformat()
 with transaction() as c:
  x=row(c,'SELECT * FROM kta_cards WHERE id=?',(id,))
  if not x:raise HTTPException(404,'Kartu tidak ditemukan')
  if x['status']!='aktif':raise HTTPException(409,'Kartu yang dibatalkan tidak dapat diubah')
  changed=[f'{k}: {x[k]} → {d[k]}' for k in ('nama','jenis_kelamin','wilayah','provinsi','terbit') if str(x[k])!=str(d[k])]
  c.execute('UPDATE kta_cards SET nama=?,jenis_kelamin=?,wilayah=?,provinsi=?,terbit=?,updated_by=?,updated_at=? WHERE id=?',(d['nama'],d['jenis_kelamin'],d['wilayah'],d['provinsi'],d['terbit'],u['id'],now(),id))
  audit(c,u['id'],'edit_kta','kta',id,f"{x['nomor']} · "+('; '.join(changed) or 'tanpa perubahan'))
  return {'ok':True}

@app.post('/api/kta/{id}/cancel')
def kta_cancel(id:int,v:KtaCancel,request:Request):
 u=user(request,True,KTA_EDITORS);note=' '.join(v.note.split())
 if len(note)<5:raise HTTPException(422,'Tuliskan alasan pembatalan (min. 5 huruf)')
 with transaction() as c:
  x=row(c,'SELECT * FROM kta_cards WHERE id=?',(id,))
  if not x or x['status']!='aktif':raise HTTPException(409,'Kartu tidak aktif')
  c.execute("UPDATE kta_cards SET status='dibatalkan',cancel_note=?,updated_by=?,updated_at=? WHERE id=?",(note[:300],u['id'],now(),id))
  audit(c,u['id'],'cancel_kta','kta',id,f"{x['nomor']} · {note}")
  return {'ok':True}

@app.get('/api/kta/export.xlsx')
def kta_export(request:Request,q:str='',tingkat:str='',status:str=''):
 from openpyxl import Workbook
 from openpyxl.styles import Font
 user(request,allowed=KTA_VIEWERS);f,args=kta_where(q,tingkat,status);c=db()
 try:items=rows(c,f'SELECT * FROM kta_cards WHERE {f} ORDER BY nomor,id',args)
 finally:c.close()
 wb=Workbook();ws=wb.active;ws.title='KTA WIB'
 ws.append(['No. KTA','Nama','Jenis Kelamin','Jabatan','Tingkat','Wilayah','Provinsi','Terbit','Status','Alasan Batal'])
 for cell in ws[1]:cell.font=Font(bold=True)
 for x in items:ws.append([x['nomor'],x['nama'],x['jenis_kelamin'],x['jabatan'],x['tingkat'],x['wilayah'],x['provinsi'],kta_card.terbit_teks(datetime.fromisoformat(x['terbit'])),x['status'],x['cancel_note'] or ''])
 for col,w in zip('ABCDEFGHIJ',(16,30,14,12,9,24,22,8,11,30)):ws.column_dimensions[col].width=w
 out=io.BytesIO();wb.save(out)
 return Response(out.getvalue(),media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',headers={'Content-Disposition':f'attachment; filename="KTA_WIB_{today()}.xlsx"'})

@app.get('/api/kta/{id}/pdf')
def kta_get_pdf(id:int,request:Request,download:int=0):
 user(request,allowed=KTA_VIEWERS);c=db()
 try:
  x=row(c,'SELECT * FROM kta_cards WHERE id=?',(id,))
  if not x:raise HTTPException(404,'Kartu tidak ditemukan')
  if x['status']!='aktif':raise HTTPException(409,'Kartu sudah dibatalkan dan tidak dapat dicetak')
  return kta_pdf([x],kta_filename(x),bool(download))
 finally:c.close()

@app.get('/api/kta/{id}/history')
def kta_history(id:int,request:Request):
 user(request,allowed=KTA_VIEWERS);c=db()
 try:return rows(c,"SELECT a.action,a.detail,a.created_at,u.full_name actor FROM audits a LEFT JOIN users u ON u.id=a.actor WHERE a.entity='kta' AND a.entity_id=? ORDER BY a.id DESC",(id,))
 finally:c.close()

# Paket KTA: Ketua, Sekretaris, dan Bendahara satu wilayah sekaligus. Nomor tiap kartu = nomor induk wilayah + kode jabatan.
# Disimpan semua atau tidak sama sekali; baris yang namanya dikosongkan dilewati.
class KtaOrang(BaseModel):jabatan:str;nama:str='';jenis_kelamin:str=''
class KtaPaket(BaseModel):tingkat:str;induk:str;wilayah:str;provinsi:str='';terbit:str='';orang:list[KtaOrang]
def kta_paket_clean(v):
 induk=v.induk.strip()
 pat={'DPW':r'\d{2}\.000','DPD':r'\d{2}\.\d{3}','DPC':r'\d{2}\.\d{3}','PAC':r'\d{2}\.\d{3}\.\d{3}'}.get(v.tingkat)
 if not pat:raise HTTPException(422,'Tingkat harus DPW, DPD, DPC, atau PAC')
 if not re.fullmatch(pat,induk):raise HTTPException(422,{'DPW':'Nomor induk DPW berformat PP.000','PAC':'Nomor induk PAC berformat PP.XXX.XXX'}.get(v.tingkat,f'Nomor induk {v.tingkat} berformat PP.XXX'))
 isi=[o for o in v.orang if o.nama.strip()]
 if not isi:raise HTTPException(422,'Isi minimal satu nama pengurus')
 if len({o.jabatan for o in isi})!=len(isi):raise HTTPException(422,'Setiap jabatan hanya boleh satu orang')
 out=[]
 for o in isi:
  if o.jabatan not in kta_card.JABATAN:raise HTTPException(422,'Jabatan harus Ketua, Sekretaris, atau Bendahara')
  try:d=kta_clean(KtaIn(nomor=f'{induk}.{kta_card.JABATAN[o.jabatan]}',nama=o.nama,jenis_kelamin=o.jenis_kelamin,jabatan=o.jabatan,tingkat=v.tingkat,wilayah=v.wilayah,provinsi=v.provinsi,terbit=v.terbit))
  except HTTPException as e:raise HTTPException(e.status_code,f'{o.jabatan}: {e.detail}')
  out.append(d)
 return sorted(out,key=lambda d:d['nomor'])
def kta_paket_name(d):return re.sub(r'[\\/:*?"<>|]+',' ',f"KTA WIB {d['tingkat']} {d['wilayah']}".upper()).strip()+'.pdf'

@app.post('/api/kta/paket/preview')
def kta_paket_preview(v:KtaPaket,request:Request):
 user(request,True,KTA_EDITORS);ds=kta_paket_clean(v);return kta_pdf(ds,'PRATINJAU '+kta_paket_name(ds[0]))

@app.post('/api/kta/paket')
def kta_paket_create(v:KtaPaket,request:Request):
 u=user(request,True,KTA_EDITORS);ds=kta_paket_clean(v);ids=[]
 with transaction() as c:
  taken=[f"{d['nomor']} ({h['nama']})" for d in ds for h in [kta_holder(c,d['nomor'])] if h]
  if taken:raise HTTPException(409,'Nomor sudah dipakai kartu aktif: '+', '.join(taken)+'. Tidak ada kartu yang disimpan. Batalkan kartu lama dahulu bila ada pergantian pengurus.')
  for d in ds:
   cur=c.execute('INSERT INTO kta_cards(nomor,nama,jenis_kelamin,jabatan,tingkat,wilayah,provinsi,terbit,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)',(d['nomor'],d['nama'],d['jenis_kelamin'],d['jabatan'],d['tingkat'],d['wilayah'],d['provinsi'],d['terbit'].isoformat(),u['id'],now()))
   audit(c,u['id'],'create_kta','kta',cur.lastrowid,f"{d['nomor']} · {d['jabatan']} {d['tingkat']} {d['wilayah']} (paket)");ids.append(cur.lastrowid)
 return {'ok':True,'ids':ids}

@app.get('/api/kta/pdf')
def kta_get_pdfs(request:Request,ids:str,download:int=0):
 """Beberapa KTA dalam satu PDF (depan & belakang per kartu, urut nomor)."""
 user(request,allowed=KTA_VIEWERS)
 try:want=[int(x) for x in ids.split(',') if x.strip()][:60]
 except ValueError:raise HTTPException(422,'Daftar kartu tidak valid')
 if not want:raise HTTPException(422,'Pilih minimal satu kartu')
 c=db()
 try:items=rows(c,f"SELECT * FROM kta_cards WHERE status='aktif' AND id IN ({','.join('?'*len(want))}) ORDER BY nomor",want)
 finally:c.close()
 if not items:raise HTTPException(404,'Kartu tidak ditemukan atau sudah dibatalkan')
 return kta_pdf(items,kta_paket_name(items[0]) if len(items)>1 else kta_filename(items[0]),bool(download))

@app.get('/api/kta/wilayah')
def kta_wilayah(request:Request):
 """Daftar induk nomor wilayah untuk pilihan di formulir KTA."""
 user(request,allowed=KTA_EDITORS);return KTA_MASTER
