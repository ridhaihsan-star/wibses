"""SK WIB format resmi: kode wilayah, penomoran, template, dan render PDF (mengikuti Template_SK_WIB.docx)."""
import io, json, re
from pathlib import Path
from datetime import date
from xml.sax.saxutils import escape
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Paragraph
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

BASE=Path(__file__).resolve().parent
REF=json.loads((BASE/'referensi'/'kode_wilayah_wib.json').read_text(encoding='utf-8'))
TINGKAT={'DPW':('DEWAN PIMPINAN WILAYAH','Wilayah','PROVINSI'),'DPD':('DEWAN PIMPINAN DAERAH','Daerah','KABUPATEN'),'DPC':('DEWAN PIMPINAN CABANG','Cabang','KOTA'),'PAC':('PIMPINAN ANAK CABANG','Anak Cabang','KECAMATAN')}
# Kode jabatan pada nomor SK. Jabatan baru ditambahkan dengan nomor berikutnya.
JABATAN_KODE={'ketua':'01','sekretaris':'02','bendahara':'03','anggota':'04'}
ROMAWI=['I','II','III','IV','V','VI','VII','VIII','IX','X','XI','XII']
BULAN=['Januari','Februari','Maret','April','Mei','Juni','Juli','Agustus','September','Oktober','November','Desember']
IMAGE_SLOTS={'kop':'Kop surat','watermark':'Watermark','logo':'Logo WIB tengah','ttd1':'Tanda tangan penandatangan 1','ttd2':'Tanda tangan penandatangan 2','stempel':'Stempel resmi WIB'}
# Sejak 4 Nov 2026 (keputusan DPP): seluruh SK, termasuk draft, memuat tanda tangan Ketua Umum dan Sekretaris Jenderal
# seperti Template_SK_WIB.docx, tanpa langkah otorisasi. Tabel sk_image_auth dibiarkan sebagai arsip.
AUTH_SLOTS=()

DEFAULT_TEMPLATE={
 'pembuka':'ATAS BERKAT RAHMAT ALLAH YANG MAHA KUASA DAN DIDORONG OLEH KEINGINAN LUHUR BERSAMA',
 'penerbit':'DEWAN PIMPINAN PUSAT - WAKTU INDONESIA BERGERAK',
 'periode':'2026 - 2031',
 'menimbang':[
  'Demi terlaksananya visi, misi serta terselenggaranya program kegiatan dalam upaya mencapai tujuan perkumpulan, maka diperlukan pengangkatan dan pengesahan Struktur Organisasi di Seluruh Republik Indonesia Masa Bhakti 2026-2031.',
  'Bahwa langkah sebagaimana dimaksud pada huruf a telah dilakukan dalam Rapat internal pengurus yang dituangkan dalam berita acara pada tanggal 05 Desember 2023, tentang Struktur Pelembagaan Waktu Indonesia Bergerak.',
  'Hasil Evaluasi pelembagaan ditingkat Internal kepengurusan DPP WIB yang tertuang dalam notulensi dan berita acara tertanggal 30 Januari 2024, tentang kepengurusan DPP WIB.',
  'Hasil Keputusan Dewan Pimpinan Pusat Waktu Indonesia Bergerak dalam menerapkan Kemandirian dan Percepatan Pembentukan Pelembagaan ditingkat Daerah, leardership and Manajemen Waktu Indonesia Bergerak, dengan Tema Satu Komando yang terdiri dari : Satu Koordinasi, satu Administrasi, Terstruktur dan terukur, khususnya dalam hal pembuatan dan Keluarnya Surat Keputusan Dewan Pimpinan {tingkat_kata}, pada tanggal 12 Juni 2024.',
  'Bahwa berdasarkan pertimbangan sebagaimana dimaksud pada huruf a, b, c dan huruf d, perlu dituangkan dalam Keputusan Dewan Pengurus {tingkat_kata} Perkumpulan Waktu Indonesia Bergerak agar menjamin kepastian hukum dalam proses kepengurusan;'],
 'mengingat':[
  'Peraturan Menkumham Nomor 6 Tahun 2014 tentang Pengesahan Badan Hukum Perkumpulan.',
  'Akte Pendirian Perkumpulan Waktu Indonesia Bergerak Nomer 18, tanggal 16 Januari 2023 Notaris Suprianto.,SH.',
  'Surat Keputusan Menteri Hukum dan Hak Asasi Manusia Republik Indonesia Nomer AHU-0002574. AH.01.07 Tahun 2023.',
  'Anggaran Dasar dan Anggaran Rumah Tangga Waktu Indonesia Bergerak'],
 'kesatu_lanjutan':'Untuk selanjutnya menyusun jajaran struktur kepengurusan selengkapnya dan menjalankan program kegiatan sesuai visi dan misi organisasi Perkumpulan Waktu Indonesia Bergerak',
 'kedua':'Keputusan ini berlaku mulai tanggal ditetapkan.',
 'kota':'Jakarta',
 'penetap':'DEWAN PIMPINAN PUSAT\nWAKTU INDONESIA BERGERAK',
 'ttd1_nama':'SITI FATIMAH,S.H.','ttd1_jabatan':'KETUA UMUM',
 'ttd2_nama':'AGUSTIN MALIK, SE','ttd2_jabatan':'SEKRETARIS JENDRAL',
 'stempel_pada':'ttd1',
 'tembusan':['Pengawas Dewan Pimpinan Pusat Waktu Indonesia Bergerak','Arsip'],
 'footer':'Telpon : +62 21 2503 3835.  WA : +62 812 9090 9029 Email : Perkumpulanwib.official@gmail.com . Facebook : Perkumpulan Wib',
}
TEXT_FIELDS=[k for k,v in DEFAULT_TEMPLATE.items() if isinstance(v,str)]
LIST_FIELDS=[k for k,v in DEFAULT_TEMPLATE.items() if isinstance(v,list)]

def clean_template(data):
 """Validasi isian template dari pengguna; field yang hilang memakai default."""
 out={}
 for k in TEXT_FIELDS:
  v=str(data.get(k,DEFAULT_TEMPLATE[k]) if data.get(k) is not None else DEFAULT_TEMPLATE[k]).strip()
  out[k]=v[:2000]
 for k in LIST_FIELDS:
  v=data.get(k,DEFAULT_TEMPLATE[k])
  if isinstance(v,str):v=v.split('\n')
  out[k]=[str(x).strip()[:2000] for x in v if str(x).strip()][:12]
 return out

# ---------- Kode wilayah ----------
def _key(s):
 s=re.sub(r'[^A-Z0-9 ]',' ',str(s or '').upper())
 s=re.sub(r'\bSUMATRA\b','SUMATERA',s);s=re.sub(r'\b(JOGYAKARTA|JOGJAKARTA|YOGJAKARTA)\b','YOGYAKARTA',s)
 s=re.sub(r'^\s*(PROVINSI|PROV)\s+','',s)
 return re.sub(r'\s+','',s)
def _split_city(s):
 """Pisahkan awalan Kabupaten/Kota. Hasil: (jenis|None, nama)."""
 t=re.sub(r'\s+',' ',str(s or '').upper().replace('.',' ')).strip()
 m=re.match(r'^(KABUPATEN|KAB)\s+(.*)$',t)
 if m:return 'KABUPATEN',m.group(2)
 m=re.match(r'^(KOTA ADMINISTRASI|KOTA ADM|KOTA)\s+(.*)$',t)
 if m:return 'KOTA',m.group(2)
 return None,t
def find_province(name):
 k=_key(name)
 if not k:return None
 for p in REF['provinsi']:
  if k in [_key(p['nama'])]+[_key(a) for a in p.get('alias',[])]:return p
 return None
def province_by_code(code):return next((p for p in REF['provinsi'] if p['kode']==code),None)
def region_by_code(prov,code):return next((w for w in prov['wilayah'] if w['kode']==code),None) if prov else None
def find_region(prov,level,city):
 if not prov or not str(city or '').strip():return None
 jenis,nama=_split_city(city);k=_key(nama)
 if not jenis and level in ('DPD','DPC'):jenis=TINGKAT[level][2]
 found=[w for w in prov['wilayah'] if (not jenis or w['jenis']==jenis) and k in [_key(w['nama'])]+[_key(a) for a in w.get('alias',[])]]
 return found[0] if len(found)==1 else None

def resolve_codes(a):
 """Kode provinsi & kab/kota untuk satu jabatan; kode manual (prov_code/city_code) didahulukan."""
 prov=province_by_code(a.get('prov_code')) if a.get('prov_code') else find_province(a['province'])
 reg=None
 if a['level']!='DPW':
  reg=region_by_code(prov,a.get('city_code')) if a.get('city_code') else find_region(prov,a['level'],a.get('city'))
 return prov,reg

def sk_number(a,prov,reg,when):
 """Nomor SK sesuai aturan DPP. None bila kode belum lengkap. PAC belum ditetapkan -> None."""
 jab=JABATAN_KODE.get(str(a['title']).strip().lower())
 if not jab or not prov or a['level']=='PAC':return None
 if a['level']=='DPW':parts=[prov['kode'],jab]
 else:
  if not reg:return None
  parts=[prov['kode'],reg['kode'],jab]
 return f"{'-'.join(parts)}/SK-DPP/{a['level']}/{ROMAWI[when.month-1]}/{when.year}"

def code_problem(a,prov,reg):
 if str(a['title']).strip().lower() not in JABATAN_KODE:return f"Kode jabatan untuk '{a['title']}' belum ditetapkan"
 if a['level']=='PAC':return None
 if not prov:return 'Provinsi tidak ditemukan pada daftar kode wilayah'
 if a['level']!='DPW' and not reg:return 'Kabupaten/kota tidak ditemukan pada daftar kode wilayah'
 return None

# ---------- Isi SK ----------
def tanggal_teks(d):return f'{d.day} {BULAN[d.month-1]} {d.year}'
def sk_fields(a,person,prov,reg):
 lengkap,kata,jenis=TINGKAT[a['level']]
 if a['level']=='DPW':nama=(prov['nama'] if prov else a['province'].upper());induk=''
 elif a['level'] in ('DPD','DPC'):
  nama=reg['nama'] if reg else _split_city(a['city'])[1];jenis=reg['jenis'] if reg else jenis;induk=''
 else:
  jenis=str(a.get('sebutan') or jenis).upper();nama=str(a['district']).upper().strip();induk=(f"{reg['jenis']} {reg['nama']}" if reg else str(a['city']).upper().strip())
 judul=f'{jenis} {nama}'+(f' {induk}' if induk else '')
 kesatu=(nama if a['level']=='DPW' else f'{jenis} {nama}')+(f' {induk}' if induk else '')
 return {'tingkat_lengkap':lengkap,'tingkat_kata':kata,'wilayah_judul':judul,'wilayah_kesatu':kesatu,
  'sapaan':'Sdri.' if str(person.get('gender') or '').lower().startswith('p') else 'Sdr.',
  'nama':person['full_name'].upper().strip(),'jabatan':str(a['title']).upper().strip()}

def docx_values(info):
 """Nilai merge field Template_SK_WIB.docx."""
 return {'NOMOR_SK':info['nomor'],'SAPAAN':info['sapaan'],'NAMA':info['nama'],'JABATAN':info['jabatan'],'TINGKAT_LENGKAP':info['tingkat_lengkap'],
  'TINGKAT_KATA':info['tingkat_kata'],'WILAYAH_JUDUL':info['wilayah_judul'],'WILAYAH_KESATU':info['wilayah_kesatu'],'TANGGAL_TEKS':tanggal_teks(info['tanggal'])}

# ---------- PDF ----------
FONT,FONT_B='Helvetica','Helvetica-Bold'
for reg_,bold in ((Path('C:/Windows/Fonts/tahoma.ttf'),Path('C:/Windows/Fonts/tahomabd.ttf')),(Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'))):
 if reg_.exists() and bold.exists():
  try:
   pdfmetrics.registerFont(TTFont('SKSans',str(reg_)));pdfmetrics.registerFont(TTFont('SKSans-Bold',str(bold)))
   pdfmetrics.registerFontFamily('SKSans',normal='SKSans',bold='SKSans-Bold',italic='SKSans',boldItalic='SKSans-Bold')
   FONT,FONT_B='SKSans','SKSans-Bold'
  except Exception:pass
  break

W,H=A4
LEFT,RIGHT,TOP,BOTTOM=72,W-50,140,70
RED=HexColor('#c00000')
BODY=ParagraphStyle('body',fontName=FONT,fontSize=10.5,leading=14.5,alignment=TA_JUSTIFY)
BODY_L=ParagraphStyle('bodyl',parent=BODY,alignment=TA_LEFT)

_IMG_CACHE={}
def _img(path,flatten=False):
 """flatten=True: gambar besar tanpa perlu transparansi (kop) dijadikan JPEG berlatar putih agar PDF kecil."""
 try:
  if not path or not Path(path).exists():return None
  if not flatten:return ImageReader(str(path))
  key=(str(path),Path(path).stat().st_mtime)
  if key not in _IMG_CACHE:
   from PIL import Image
   im=Image.open(path).convert('RGBA');bg=Image.new('RGB',im.size,'white');bg.paste(im,mask=im.split()[3])
   out=io.BytesIO();bg.save(out,'JPEG',quality=90,optimize=True);_IMG_CACHE.clear();_IMG_CACHE[key]=out.getvalue()
  return ImageReader(io.BytesIO(_IMG_CACHE[key]))
 except Exception:return None

def render_pdf(info,tpl,images):
 """info: nomor, draft, tanggal(date) + sk_fields. images: slot -> path. Hasil: bytes PDF."""
 def fill(s):
  try:return s.format_map(_Safe(info))
  except (ValueError,IndexError,AttributeError):return s
 buf=io.BytesIO();cv=canvas.Canvas(buf,pagesize=A4)
 cv.setTitle(f"SK {info['nama']} - {info['jabatan']} {info['tingkat_lengkap']}");cv.setAuthor('Perkumpulan Waktu Indonesia Bergerak')
 kop=_img(images.get('kop'),flatten=True);wm,logo,t1,t2,stamp=(_img(images.get(k)) for k in ('watermark','logo','ttd1','ttd2','stempel'))
 state={'y':0}
 def page_frame():
  if wm:
   iw,ih=wm.getSize();ww=380;wh=ww*ih/iw;cv.drawImage(wm,(W-ww)/2,(H-wh)/2-30,ww,wh,mask='auto')
  if kop:
   iw,ih=kop.getSize();kw=455;kh=kw*ih/iw;cv.drawImage(kop,(W-kw)/2,H-10-kh,kw,kh,mask='auto')
  else:
   cv.setFont(FONT_B,15);cv.drawCentredString(W/2,H-50,'PERKUMPULAN WAKTU INDONESIA BERGERAK (WIB)');cv.setStrokeColor(RED);cv.setLineWidth(1.5);cv.line(40,H-70,W-40,H-70)
  cv.setFillColor(RED);cv.rect(0,0,W,20,fill=1,stroke=0);cv.setFillColor(HexColor('#ffffff'));cv.setFont(FONT,6.5);cv.drawCentredString(W/2,7,tpl['footer'][:200]);cv.setFillColor(HexColor('#000000'))
  if info['draft']:
   cv.saveState();cv.setFillColor(HexColor('#94a3b8'));cv.setFillAlpha(0.35);cv.translate(W/2,H/2);cv.rotate(40);cv.setFont(FONT_B,90);cv.drawCentredString(0,0,'DRAFT');cv.restoreState()
  state['y']=H-TOP
 def new_page():cv.showPage();page_frame()
 def need(h):
  if state['y']-h<BOTTOM:new_page()
 def center(text,size=10.5,bold=False,gap=None):
  need(size+4);cv.setFont(FONT_B if bold else FONT,size);cv.drawCentredString(W/2,state['y']-size,text);state['y']-=gap or size*1.35
 def para(html,x,width,style=BODY,space=6):
  p=Paragraph(html,style);_,h=p.wrap(width,H);need(h);p.drawOn(cv,x,state['y']-h);state['y']-=h+space;return h
 def item(label,marker,html,space=8):
  # Kolom: label | ":" | penanda | teks
  p=Paragraph(html,BODY);_,h=p.wrap(RIGHT-200,H);need(h)
  top=state['y']
  cv.setFont(FONT,10.5)
  if label:cv.drawString(LEFT+18,top-11,label);cv.drawString(LEFT+95,top-11,':')
  if marker:cv.drawString(LEFT+110,top-11,marker)
  p.drawOn(cv,200,top-h);state['y']-=h+space

 page_frame()
 center(tpl['pembuka'],9.5,gap=34)
 center('SURAT KEPUTUSAN',11,True,15);center(tpl['penerbit'],11,True,15)
 center('Nomor: '+info['nomor'],11,True,15);center('PERIODE TAHUN '+tpl['periode'],11,True,32)
 center('TENTANG',11,True,18)
 center('PENGANGKATAN '+info['tingkat_lengkap'],14,True,18);center('WAKTU INDONESIA BERGERAK',14,True,18);center(info['wilayah_judul'],14,True,40)
 for i,t in enumerate(tpl['menimbang']):item('Menimbang' if i==0 else '',f'{chr(97+i)}.',escape(fill(t)))
 new_page()
 for i,t in enumerate(tpl['mengingat']):item('Mengingat' if i==0 else '',f'{i+1}.',escape(fill(t)))
 state['y']-=6;center('MEMUTUSKAN:',10.5,True,26)
 need(40);cv.setFont(FONT,10.5);cv.drawString(LEFT+18,state['y']-11,'Menetapkan');cv.drawString(LEFT+95,state['y']-11,':');state['y']-=26
 kesatu=f"{escape(info['sapaan'])} <b>{escape(info['nama'])}</b> sebagai <b>{escape(info['jabatan'])} {escape(info['tingkat_lengkap'])} {escape(info['wilayah_kesatu'])}</b>"
 cv.setFont(FONT,10.5);need(30);cv.drawString(LEFT+18,state['y']-11,'Kesatu');cv.drawString(LEFT+95,state['y']-11,':')
 para(kesatu,200,RIGHT-200,space=10);para(escape(fill(tpl['kesatu_lanjutan'])),200,RIGHT-200,space=28)
 item('Kedua','',escape(fill(tpl['kedua'])),space=22)
 need(230)
 center(f"Ditetapkan di {tpl['kota']}, pada tanggal {tanggal_teks(info['tanggal'])}",10.5,gap=30)
 for line in tpl['penetap'].split('\n'):center(line.strip(),10.5,gap=14.5)
 # Tata letak pengesahan mengikuti Template_SK_WIB.docx (posisi & ukuran gambar dalam pt dari tepi kiri halaman,
 # vertikal dari atas baris "WAKTU INDONESIA BERGERAK"): logo di bawah, tanda tangan di atasnya.
 p0=state['y']+14.5;sx1,sx2=191,426
 def box(img,x,top,bw,bh):
  # Seperti Word: gambar mengisi kotak templat; bila proporsinya jauh berbeda, dipasang proporsional agar tidak gepeng.
  iw,ih=img.getSize();r=(iw/ih)/(bw/bh)
  if 0.75<=r<=1.34:dw,dh=bw,bh
  else:s=min(bw/iw,bh/ih);dw,dh=iw*s,ih*s
  cv.drawImage(img,x+(bw-dw)/2,p0-top-bh+(bh-dh)/2,dw,dh,mask='auto')
 if logo:box(logo,251.7,40.85,126.25,73.85)
 # Stempel resmi (bila ada) di lapisan bawah tanda tangan, sehingga tanda tangan menimpa sebagian stempel.
 if stamp:
  scx=sx2-40 if tpl.get('stempel_pada')=='ttd2' else 236
  box(stamp,scx-45,32,90,90)
 if t1:box(t1,80.4,15.4,258.4,137.4)
 if t2:box(t2,338.9,33.4,135.5,89.36)
 yn=p0-135
 for cx,nm,jb in ((sx1,tpl['ttd1_nama'],tpl['ttd1_jabatan']),(sx2,tpl['ttd2_nama'],tpl['ttd2_jabatan'])):
  cv.setFont(FONT_B,10.5);cv.drawCentredString(cx,yn,nm);tw=pdfmetrics.stringWidth(nm,FONT_B,10.5);cv.setLineWidth(0.7);cv.line(cx-tw/2,yn-1.8,cx+tw/2,yn-1.8)
  cv.drawCentredString(cx,yn-13,jb)
 state['y']=yn-48
 if tpl['tembusan']:
  need(20+15*len(tpl['tembusan']));cv.setFont(FONT_B,10.5);cv.drawString(LEFT,state['y'],'Tembusan:');state['y']-=15;cv.setFont(FONT,10.5)
  for i,t in enumerate(tpl['tembusan']):cv.drawString(LEFT,state['y'],f'{i+1}.');cv.drawString(LEFT+18,state['y'],fill(t)[:110]);state['y']-=14.5
 cv.showPage();cv.save();return buf.getvalue()

class _Safe(dict):
 def __missing__(self,k):return '{'+k+'}'

# ---------- Data_SK_WIB.xlsx (database pengurus) & unduh SK massal ----------
DATA_SK_SKIP_KET=('DIBERHENTIKAN','TIDAK AKTIF','MENINGGAL')
DATA_SK_REQUIRED=('PROVINSI','TINGKAT','WILAYAH_NAMA','JABATAN','NAMA')
DATA_SK_COLS=('PROVINSI','TINGKAT','WILAYAH_NAMA','SEBUTAN_KHUSUS','WILAYAH_INDUK','JABATAN','NAMA','JK','NO_HP','KET_KOLOM_A','KET_ADA','NOMOR_SK')

def _cell(v):return re.sub(r'\s+',' ',str(v)).strip() if v is not None else ''
def parse_tanggal(v):
 """Tanggal SK dari sel Excel: tanggal Excel, 2026-07-15, 15/07/2026, 15-07-2026, atau 15 Juli 2026.
 Hasil (date|None, teks asli); None bila kosong atau tidak terbaca."""
 from datetime import date,datetime as dt
 if v is None or v=='':return None,''
 if isinstance(v,dt):return v.date(),v.date().isoformat()
 if isinstance(v,date):return v,v.isoformat()
 t=_cell(v)
 try:
  m=re.fullmatch(r'(\d{4})-(\d{1,2})-(\d{1,2})',t)
  if m:return date(int(m[1]),int(m[2]),int(m[3])),t
  m=re.fullmatch(r'(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})',t)
  if m:return date(int(m[3]),int(m[2]),int(m[1])),t
  m=re.fullmatch(r'(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})',t)
  if m:
   bulan=[b.lower() for b in BULAN]+['jan','feb','mar','apr','mei','jun','jul','agu','sep','okt','nov','des']
   k=m[2].lower()
   if k in bulan:return date(int(m[3]),bulan.index(k)%12+1,int(m[1])),t
 except ValueError:pass
 return None,t
def parse_tanggal(v):
 """Tanggal SK dari sel Excel: tanggal Excel, 2026-07-15, 15/07/2026, 15-07-2026, atau 15 Juli 2026.
 Hasil (date|None, teks asli); None bila kosong atau tidak terbaca."""
 from datetime import date,datetime as dt
 if v is None or v=='':return None,''
 if isinstance(v,dt):return v.date(),v.date().isoformat()
 if isinstance(v,date):return v,v.isoformat()
 t=_cell(v)
 try:
  m=re.fullmatch(r'(\d{4})-(\d{1,2})-(\d{1,2})',t)
  if m:return date(int(m[1]),int(m[2]),int(m[3])),t
  m=re.fullmatch(r'(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})',t)
  if m:return date(int(m[3]),int(m[2]),int(m[1])),t
  m=re.fullmatch(r'(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})',t)
  if m:
   bulan=[b.lower() for b in BULAN]+['jan','feb','mar','apr','mei','jun','jul','agu','sep','okt','nov','des']
   k=m[2].lower()
   if k in bulan:return date(int(m[3]),bulan.index(k)%12+1,int(m[1])),t
 except ValueError:pass
 return None,t
def parse_tanggal(v):
 """Tanggal SK dari sel Excel: tanggal Excel, 2026-07-15, 15/07/2026, 15-07-2026, atau 15 Juli 2026.
 Hasil (date|None, teks asli); None bila kosong atau tidak terbaca."""
 from datetime import date,datetime as dt
 if v is None or v=='':return None,''
 if isinstance(v,dt):return v.date(),v.date().isoformat()
 if isinstance(v,date):return v,v.isoformat()
 t=_cell(v)
 try:
  m=re.fullmatch(r'(\d{4})-(\d{1,2})-(\d{1,2})',t)
  if m:return date(int(m[1]),int(m[2]),int(m[3])),t
  m=re.fullmatch(r'(\d{1,2})[/.-](\d{1,2})[/.-](\d{4})',t)
  if m:return date(int(m[3]),int(m[2]),int(m[1])),t
  m=re.fullmatch(r'(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})',t)
  if m:
   bulan=[b.lower() for b in BULAN]+['jan','feb','mar','apr','mei','jun','jul','agu','sep','okt','nov','des']
   k=m[2].lower()
   if k in bulan:return date(int(m[3]),bulan.index(k)%12+1,int(m[1])),t
 except ValueError:pass
 return None,t
def _safe_name(s):return re.sub(r'[\\/:*?"<>|]+',' ',s).strip()[:150]
def nice(s):
 """JAWA BARAT -> Jawa Barat, DKI JAKARTA -> DKI Jakarta (gaya penulisan wilayah di aplikasi)."""
 t=' '.join(w.capitalize() for w in str(s or '').split())
 return re.sub(r'\b(Dki|Di|Ii|Iii|Iv)\b',lambda m:m.group(0).upper(),t)

def read_data_sk(data):
 """Baris sheet Data_SK dari Data_SK_WIB.xlsx; None bila berkas bukan format ini."""
 from openpyxl import load_workbook
 try:wb=load_workbook(io.BytesIO(data),read_only=True,data_only=True)
 except Exception:return None
 if 'Data_SK' not in wb.sheetnames:return None
 it=wb['Data_SK'].iter_rows(values_only=True)
 header=[_cell(h).upper() for h in next(it,())];col={h:i for i,h in enumerate(header) if h}
 missing=[h for h in DATA_SK_REQUIRED if h not in col]
 if missing:raise ValueError('Kolom wajib tidak ditemukan di sheet Data_SK: '+', '.join(missing))
 out=[]
 for n,r in enumerate(it,2):
  d={h:_cell(r[col[h]]) if h in col and col[h]<len(r) else '' for h in DATA_SK_COLS}
  if not d['PROVINSI'] and not d['NAMA']:continue
  d['TINGKAT']=d['TINGKAT'].upper();d['_row']=n
  d['_tanggal'],d['TANGGAL']=parse_tanggal(r[col['TANGGAL']] if 'TANGGAL' in col and col['TANGGAL']<len(r) else None)
  out.append(d)
 return out

def data_sk_skip_reason(d):
 if not d['NAMA']:return 'Nama kosong (jabatan belum terisi)'
 ket=f"{d['KET_KOLOM_A']} {d['KET_ADA']}".upper()
 if any(k in ket for k in DATA_SK_SKIP_KET):return 'Keterangan: '+(d['KET_ADA'] or d['KET_KOLOM_A'])
 if d['TINGKAT'] not in TINGKAT:return f"Tingkat '{d['TINGKAT']}' tidak dikenal"
 if str(d['JABATAN']).strip().lower() not in JABATAN_KODE:return f"Kode jabatan untuk '{d['JABATAN']}' belum ditetapkan"
 return None

def bulk_zip(out,items,tpl,images,report):
 """items: dict(folder, name, info, row) per SK. Tulis ZIP berisi PDF per provinsi, Daftar_SK.xlsx, dan LAPORAN.txt ke `out`."""
 import zipfile
 from openpyxl import Workbook
 wb=Workbook();ws=wb.active;ws.title='Daftar_SK'
 ws.append(['NO','PROVINSI','TINGKAT','WILAYAH','JABATAN','NAMA','JK','NO_HP','NOMOR_SK','TANGGAL','FILE PDF'])
 used=set()
 with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
  for i,x in enumerate(items,1):
   path=f"{_safe_name(x['folder'])}/{_safe_name(x['name'])}.pdf"
   if path in used:path=path[:-4]+f' ({i}).pdf'
   used.add(path);z.writestr(path,render_pdf(x['info'],tpl,images))
   ws.append([i]+list(x['row'])+[path])
   ws.cell(row=i+1,column=10).number_format='DD/MM/YYYY'
  for letter,w in zip('ABCDEFGHIJK',(6,26,9,40,13,34,5,17,30,12,60)):ws.column_dimensions[letter].width=w
  xbuf=io.BytesIO();wb.save(xbuf);z.writestr('Daftar_SK.xlsx',xbuf.getvalue())
  z.writestr('LAPORAN.txt','\r\n'.join(report)+'\r\n')
