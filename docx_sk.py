"""SK WIB versi Word: isi merge field «...» pada Template_SK_WIB.docx tanpa mengubah tata letak."""
import copy, io, os, re, zipfile, hashlib
from lxml import etree

W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
XML_SPACE='{http://www.w3.org/XML/1998/namespace}space'
q=lambda tag:f'{{{W}}}{tag}'
FIELDS=('NOMOR_SK','SAPAAN','NAMA','JABATAN','TINGKAT_LENGKAP','TINGKAT_KATA','WILAYAH_JUDUL','WILAYAH_KESATU','TANGGAL_TEKS')
PARTS=re.compile(r'^word/(document|header\d*|footer\d*)\.xml$')

def _text(r):return ''.join(e.text or '' for e in r if e.tag==q('t'))
def _fld(r):
 f=r.find(q('fldChar'));return f.get(q('fldCharType')) if f is not None else None

def _fields(root):
 """Daftar field kompleks: (nama, [run...] dari begin s.d. end, run hasil atau None)."""
 out=[]
 for p in root.iter(q('p')):
  runs=list(p.iter(q('r')));i=0
  while i<len(runs):
   if _fld(runs[i])!='begin':i+=1;continue
   j=i;instr='';result=None;sep=False
   while j<len(runs) and _fld(runs[j])!='end':
    it=runs[j].find(q('instrText'))
    if it is not None:instr+=it.text or ''
    if _fld(runs[j])=='separate':sep=True
    elif sep and result is None and runs[j].find(q('t')) is not None:result=runs[j]
    j+=1
   m=re.match(r'\s*MERGEFIELD\s+"?([A-Za-z0-9_]+)',instr)
   out.append((m.group(1).upper() if m else None,runs[i:j+1],result));i=j+1
 return out

def _set_text(r,value):
 for t in r.findall(q('t'))[1:]:r.remove(t)
 t=r.find(q('t'))
 if t is None:t=etree.SubElement(r,q('t'))
 t.text=value;t.set(XML_SPACE,'preserve')

def _field_runs(name,like):
 """Run field MERGEFIELD baru dengan format (rPr) seperti `like`."""
 rpr=like.find(q('rPr'))
 def run(child=None,text=None):
  r=etree.Element(q('r'))
  if rpr is not None:r.append(copy.deepcopy(rpr))
  if child is not None:r.append(child)
  if text is not None:
   t=etree.SubElement(r,q('t'));t.text=text;t.set(XML_SPACE,'preserve')
  return r
 fc=lambda kind:etree.Element(q('fldChar'),{q('fldCharType'):kind})
 it=etree.Element(q('instrText'));it.text=f' MERGEFIELD {name} ';it.set(XML_SPACE,'preserve')
 return [run(fc('begin')),run(it),run(fc('separate')),run(text=f'«{name}»'),run(fc('end'))]

def _replace_run_with_field(r,name):
 parent=r.getparent();pos=parent.index(r)
 for k,new in enumerate(_field_runs(name,r)):parent.insert(pos+k,new)
 parent.remove(r)

def normalize_template(data):
 """Template_SK_WIB.docx bawaan masih memuat contoh isian tertulis langsung (nama, jabatan, contoh nomor,
 tanggal). Ubah menjadi field «NAMA» «JABATAN» dan hapus contoh nomor & tanggal. Template yang sudah
 memakai field tidak berubah."""
 zin=zipfile.ZipFile(io.BytesIO(data));root=etree.fromstring(zin.read('word/document.xml'))
 names={n for n,_,_ in _fields(root)}
 for p in root.iter(q('p')):
  runs=[r for r in p.iter(q('r'))];text=''.join(_text(r) for r in runs)
  if text.strip().startswith('Nomor:') and 'NOMOR_SK' in ''.join(''.join(p.itertext()).split()):
   # buang contoh nomor di antara "Nomor: " dan field NOMOR_SK
   started=False
   for r in runs:
    if _fld(r)=='begin':break
    if started and _text(r):_set_text(r,'')
    if _text(r).startswith('Nomor:'):_set_text(r,'Nomor: ');started=True
  if 'sebagai' in text and 'NAMA' not in names:
   body=[r for r in runs if _text(r).strip()]
   k=next((i for i,r in enumerate(body) if _text(r).strip()=='sebagai'),None)
   if k:
    _replace_run_with_field(body[k-1],'NAMA')
    if k+1<len(body) and not _fld(body[k+1]):_replace_run_with_field(body[k+1],'JABATAN')
  if text.strip().startswith('Ditetapkan di'):
   for r in runs:
    if re.fullmatch(r'\s*\d{1,2}\s+[A-Za-z]+\s+\d{4}\s*',_text(r)):_set_text(r,'')
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for item in zin.infolist():
   z.writestr(item,etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True) if item.filename=='word/document.xml' else zin.read(item.filename))
 return out.getvalue()

def template_fields(data):
 """Nama field yang ada di template (untuk validasi unggahan)."""
 zin=zipfile.ZipFile(io.BytesIO(data));found=set()
 for name in zin.namelist():
  if PARTS.match(name):found|={n for n,_,_ in _fields(etree.fromstring(zin.read(name))) if n}
 return found

def fill(data,values):
 """Isi setiap MERGEFIELD dengan nilai di `values` (kunci = nama field). Field menjadi teks biasa."""
 zin=zipfile.ZipFile(io.BytesIO(data));out=io.BytesIO()
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for item in zin.infolist():
   raw=zin.read(item.filename)
   if item.filename=='word/settings.xml':raw=_drop_mailmerge(raw)
   if PARTS.match(item.filename):
    root=etree.fromstring(raw)
    for name,runs,result in _fields(root):
     if name not in values:continue
     keep=result if result is not None else runs[0]
     for r in runs:
      if r is not keep:r.getparent().remove(r)
     for child in list(keep):
      if child.tag in (q('fldChar'),q('instrText')):keep.remove(child)
     _set_text(keep,str(values[name]))
    raw=etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True)
   z.writestr(item,raw)
 return out.getvalue()

def _drop_mailmerge(raw):
 """Lepas tautan mail merge ke file Excel di komputer pembuat template; tanpa ini Word bertanya soal sumber data."""
 root=etree.fromstring(raw)
 for m in root.findall(q('mailMerge')):root.remove(m)
 return etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True)

# ---------- SK SES (Koordinator Wilayah, Kepala Cabang, Kepala Unit) ----------
SES_FIELDS=('NOMOR_SK','SAPAAN','NAMA','WILAYAH','WILAYAH_BESAR','TANGGAL_TEKS')
# KANCAB: KABUPATEN__KOTA(1); KANWIL: PROVINSI / Provinsi1 / NAMA_KETUA; KANTOR UNIT: Nama_Unit
SES_RENAME={'KABUPATEN__KOTA1':'WILAYAH_BESAR','KABUPATEN__KOTA':'WILAYAH','PROVINSI':'WILAYAH_BESAR','PROVINSI1':'WILAYAH','NAMA_KETUA':'NAMA','NAMA_UNIT':'WILAYAH'}

def _insert_field_after(r,name,like=None):
 parent=r.getparent();pos=parent.index(r)+1
 for k,new in enumerate(_field_runs(name,like if like is not None else r)):parent.insert(pos+k,new)

def normalize_ses_template(data):
 """Template SK KEPALA KANCAB (mail merge dari Table Wilayah SES Group.xlsx) -> field yang diisi app:
 nomor (No_Daerah-No_Wilayah.01/SES-GROUP/bulan/tahun) menjadi satu field «NOMOR_SK», sapaan «SAPAAN»,
 tanggal penetapan «TANGGAL_TEKS», dan nama wilayah «WILAYAH» / «WILAYAH_BESAR». Template yang sudah
 memakai field ini tidak berubah."""
 zin=zipfile.ZipFile(io.BytesIO(data));root=etree.fromstring(zin.read('word/document.xml'))
 # Nama_Unit hanya satu field; di kalimat berhuruf kapital (judul) dipakai versi kapital
 for p in root.iter(q('p')):
  fs=[(n,runs) for n,runs,_ in _fields(p) if n=='NAMA_UNIT']
  if not fs:continue
  inside={id(r) for _,runs in fs for r in runs}
  static=''.join(_text(r) for r in p.iter(q('r')) if id(r) not in inside)
  if re.search(r'[A-Za-z]',static) and static==static.upper():
   for _,runs in fs:
    for r in runs:
     it=r.find(q('instrText'))
     if it is not None and 'MERGEFIELD' in (it.text or ''):it.text=' MERGEFIELD WILAYAH_BESAR '
 for it in root.iter(q('instrText')):
  m=re.match(r'(\s*MERGEFIELD\s+"?)([A-Za-z0-9_]+)(.*)$',it.text or '',re.S)
  if m and m.group(2).upper() in SES_RENAME:it.text=f' MERGEFIELD {SES_RENAME[m.group(2).upper()]} '
 for p in root.iter(q('p')):
  runs=list(p.iter(q('r')));text=''.join(_text(r) for r in runs)
  names={n for n,_,_ in _fields(p)}
  if re.match(r'\s*Nomor\s*:',text) and 'NOMOR_SK' not in names and ({'NO','NO_DAERAH','NO_WILAYAH','NO_UNIT'}&names or 'SES-GROUP' in text):
   # semua isi setelah "Nomor :" diganti satu field nomor
   colon=next(r for r in runs if ':' in _text(r));after=runs[runs.index(colon)+1:]
   like=next((r for r in after if _text(r).strip()),colon)
   _insert_field_after(colon,'NOMOR_SK',like)
   for r in after:r.getparent().remove(r)
   if not _text(colon).endswith(' '):_set_text(colon,_text(colon)+' ')
  elif re.match(r'\s*Pada\s+tanggal\s*:',text) and 'TANGGAL_TEKS' not in names:
   colon=next(r for r in runs if ':' in _text(r));after=runs[runs.index(colon)+1:]
   _insert_field_after(colon,'TANGGAL_TEKS',next((r for r in after if _text(r).strip()),colon))
   for r in after:r.getparent().remove(r)
   _set_text(colon,_text(colon).rstrip()+' ')
  if 'SAPAAN' not in names:
   for r in runs:
    if _text(r).strip() in ('Sdr.','Sdri.') and not _fld(r):_replace_run_with_field(r,'SAPAAN')
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for item in zin.infolist():
   raw=zin.read(item.filename)
   if item.filename=='word/document.xml':raw=etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True)
   elif item.filename=='word/settings.xml':raw=_drop_mailmerge(raw)
   z.writestr(item,raw)
 return out.getvalue()

SES_FIT_REF={'NAMA':'ATINI SASTRA','WILAYAH':'Kabupaten Aceh Tenggara','WILAYAH_BESAR':'KABUPATEN ACEH TENGGARA'}
def fit_first_page(data,values,ref=SES_FIT_REF):
 """SK SES dirancang satu halaman keputusan + satu halaman tugas. Isian yang lebih panjang dari contoh yang muat
 (mis. "Kecamatan …, Kabupaten …") menambah baris sehingga blok tanda tangan menimpa footer. Perkirakan tambahan
 baris pada paragraf berisi field, lalu hapus sebanyak itu paragraf kosong pemisah di halaman 1."""
 zin=zipfile.ZipFile(io.BytesIO(data));root=etree.fromstring(zin.read('word/document.xml'))
 body=root.find(q('body'));paras=[p for p in body if p.tag==q('p')]
 heads=[i for i,p in enumerate(paras) if ''.join(p.itertext()).strip().startswith('SURAT KEPUTUSAN')]
 page1=paras[:heads[1]] if len(heads)>1 else paras
 def lines(text,caps):return -(-len(text)//(40 if caps else 68))
 extra=0
 for p in page1:
  fs=_fields(p)
  if not any(n in values for n,_,_ in fs):continue
  inside={id(r) for _,runs,_ in fs for r in runs};static=''.join(_text(r) for r in p.iter(q('r')) if id(r) not in inside)
  caps=bool(re.search(r'[A-Za-z]',static)) and static==static.upper()
  got=static+''.join(str(values.get(n,'')) for n,_,_ in fs);base=static+''.join(ref.get(n,str(values.get(n,''))) for n,_,_ in fs)
  extra+=max(0,lines(got,caps)-lines(base,caps))
 if extra<=0:return data
 blank=lambda p:not ''.join(p.itertext()).strip() and p.find('.//'+q('drawing')) is None and p.find('.//'+q('sectPr')) is None and p.find('.//'+q('br')) is None
 stop=next((i for i,p in enumerate(page1) if ''.join(p.itertext()).strip().startswith('Ditetapkan')),len(page1))
 spacers=[p for i,p in enumerate(page1[:stop]) if i>0 and blank(p)]
 for p in spacers[:extra]:body.remove(p)
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for item in zin.infolist():
   z.writestr(item,etree.tostring(root,xml_declaration=True,encoding='UTF-8',standalone=True) if item.filename=='word/document.xml' else zin.read(item.filename))
 return out.getvalue()

# ---------- Word -> PDF (Microsoft Word di komputer server) ----------
import atexit, subprocess, tempfile, threading
from pathlib import Path
# Satu proses Word dibiarkan terbuka: ekspor pertama butuh ±50 detik (Word memeriksa printer),
# ekspor berikutnya di sesi yang sama < 1 detik.
_WORKER=r"""$ErrorActionPreference='Stop'
$w=New-Object -ComObject Word.Application;$w.Visible=$false;$w.DisplayAlerts=0
try{
[Console]::Out.WriteLine('READY');[Console]::Out.Flush()
while($null -ne ($line=[Console]::In.ReadLine())){
 if($line -eq 'QUIT'){break}
 $src,$dst=$line -split '\|',2
 try{$d=$w.Documents.Open($src,$false,$true,$false);$d.ExportAsFixedFormat($dst,17);$d.Close(0);[Console]::Out.WriteLine('OK')}
 catch{[Console]::Out.WriteLine('ERR '+($_.Exception.Message -replace '\s+',' '))}
 [Console]::Out.Flush()}
}finally{$w.Quit()}"""
_LOCK=threading.Lock();_proc=None
def word_available():return os.name=='nt' and any(Path(x).exists() for x in (r'C:\Program Files\Microsoft Office',r'C:\Program Files (x86)\Microsoft Office'))
def _worker():
 global _proc
 if _proc and _proc.poll() is None:return _proc
 script=Path(tempfile.gettempdir())/'wib_ses_word_worker.ps1';script.write_text(_WORKER,encoding='utf-8-sig')
 _proc=subprocess.Popen(['powershell','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
 if (_proc.stdout.readline() or '').strip()!='READY':
  _proc.kill();_proc=None;raise RuntimeError('Microsoft Word tidak dapat dijalankan di komputer server')
 return _proc
def _stop():
 if _proc and _proc.poll() is None:
  try:_proc.stdin.write('QUIT\n');_proc.stdin.flush();_proc.wait(15)
  except Exception:_proc.kill()
atexit.register(_stop)
def _convert(src,dst):
 for attempt in (1,2):
  try:
   w=_worker();w.stdin.write(f'{src}|{dst}\n');w.stdin.flush();ans=(w.stdout.readline() or '').strip()
   if ans=='OK':return
   if ans.startswith('ERR'):raise RuntimeError('Konversi PDF lewat Microsoft Word gagal: '+ans[4:300])
   raise OSError('Proses Word berhenti')
  except (OSError,ValueError):
   global _proc
   if _proc:_proc.kill();_proc=None
   if attempt==2:raise RuntimeError('Proses Microsoft Word berhenti saat membuat PDF')
def warm_up():
 """Jalankan Word dan lakukan ekspor pertama (yang lambat) di latar belakang saat server mulai."""
 def run():
  try:
   with _LOCK,tempfile.TemporaryDirectory() as tmp:
    src=Path(tmp)/'warm.docx';src.write_bytes(_blank_docx());_convert(str(src),str(Path(tmp)/'warm.pdf'))
  except Exception:pass
 if word_available():threading.Thread(target=run,daemon=True).start()
def _blank_docx():
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w') as z:
  z.writestr('[Content_Types].xml','<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
  z.writestr('_rels/.rels','<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
  z.writestr('word/document.xml',f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="{W}"><w:body><w:p><w:r><w:t>.</w:t></w:r></w:p></w:body></w:document>')
 return out.getvalue()
def to_pdf(data,cache_dir=None):
 """docx -> PDF lewat Microsoft Word supaya hasilnya sama persis dengan Word. Hasil disimpan di `cache_dir`
 berdasarkan isi docx, jadi unduhan berikutnya tidak membuka Word lagi."""
 return to_pdfs([data],cache_dir)[0]
def to_pdfs(datas,cache_dir=None):
 if not word_available():raise RuntimeError('PDF SK SES dibuat lewat Microsoft Word, yang tidak tersedia di server ini. Unduh versi Word.')
 cache=Path(cache_dir) if cache_dir else None;out=[None]*len(datas)
 with _LOCK,tempfile.TemporaryDirectory() as tmp:
  for i,data in enumerate(datas):
   key=hashlib.sha1(data).hexdigest();hit=cache/f'{key}.pdf' if cache else None
   if hit and hit.exists():out[i]=hit.read_bytes();continue
   src=Path(tmp)/f'{i}.docx';dst=Path(tmp)/f'{i}.pdf';src.write_bytes(data);_convert(str(src),str(dst))
   out[i]=dst.read_bytes()
   if hit:cache.mkdir(parents=True,exist_ok=True);hit.write_bytes(out[i])
 return out
