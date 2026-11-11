"""KTA WIB (input manual): kartu dua sisi mengikuti desain Canva "KTA WIB" (255 x 163,5 pt).
Latar depan/belakang diambil dari PDF Canva dengan teks isian dihapus; isian ditulis ulang pada posisi aslinya."""
import io, re
from datetime import date
from pathlib import Path
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

BASE=Path(__file__).resolve().parent
FONTS=BASE/'referensi'/'fonts';ART=BASE/'referensi'/'kta'
W,H=255,163.5
for name,file in (('Montserrat','Montserrat-Regular.ttf'),('OpenSansCondBold','OpenSans-CondensedBold.ttf')):
 pdfmetrics.registerFont(TTFont(name,str(FONTS/file)))

JABATAN={'Ketua':'001','Sekretaris':'002','Bendahara':'003'}
TINGKAT={'DPW':'Dewan Pimpinan Wilayah','DPD':'Dewan Pimpinan Daerah','DPC':'Dewan Pimpinan Cabang','PAC':'Pimpinan Anak Cabang'}
GENDER=('Laki-Laki','Perempuan')

def number_problem(nomor,tingkat,jabatan):
 """Format nomor: DPW PP.000.JJJ · DPD/DPC PP.XXX.JJJ · PAC PP.XXX.XXX.JJJ (JJJ = kode jabatan)."""
 parts=nomor.split('.')
 if not re.fullmatch(r'\d{2}\.\d{3}(\.\d{3}){1,2}',nomor):return 'Nomor KTA harus berformat PP.XXX.JJJ atau PP.XXX.XXX.JJJ (angka dengan titik)'
 if parts[0]=='00':return 'Kode provinsi tidak boleh 00'
 if parts[-1]!=JABATAN[jabatan]:return f'Kode jabatan {jabatan} adalah {JABATAN[jabatan]}, bukan {parts[-1]}'
 if tingkat=='PAC':
  if len(parts)!=4 or parts[1]=='000' or parts[2]=='000':return 'Nomor PAC harus berformat PP.XXX.XXX.JJJ (induk DPD/DPC + nomor kecamatan)'
 elif len(parts)!=3:return f'Nomor {tingkat} harus berformat PP.XXX.JJJ'
 elif tingkat=='DPW' and parts[1]!='000':return 'Nomor DPW harus berformat PP.000.JJJ'
 elif tingkat in ('DPD','DPC') and parts[1]=='000':return f'Nomor {tingkat} tidak boleh memakai induk 000 (khusus DPW)'
 return None

def terbit_teks(d):return f'{d.month:02d}/{d.year%100:02d}'

def _fit(cv,text,font,size,maxw):
 while size>3.5 and pdfmetrics.stringWidth(text,font,size)>maxw:size-=0.25
 cv.setFont(font,size);return size

def render(cards):
 """cards: list of dict(nomor,nama,jenis_kelamin,jabatan,tingkat,wilayah,terbit[date]). Hasil: PDF (depan & belakang per kartu)."""
 buf=io.BytesIO();cv=canvas.Canvas(buf,pagesize=(W,H));cv.setTitle('KTA WIB');cv.setAuthor('Perkumpulan Waktu Indonesia Bergerak')
 front,back=ImageReader(str(ART/'kta_depan.png')),ImageReader(str(ART/'kta_belakang.png'))
 for k in cards:
  # Depan: nomor KTA di bawah QR, bulan/tahun terbit putih di pojok kanan bawah.
  cv.drawImage(front,0,0,W,H)
  cv.setFillColor(HexColor('#000000'));cv.setFont('Montserrat',16)
  cv.drawString(15.4,57.92,k['nomor'],charSpace=0.717)
  cv.setFillColor(HexColor('#ffffff'));cv.setFont('OpenSansCondBold',9);cv.drawString(213.03,13.35,terbit_teks(k['terbit']))
  cv.showPage()
  # Belakang: isian setelah label Nama s.d. Wilayah.
  cv.drawImage(back,0,0,W,H);cv.setFillColor(HexColor('#000000'))
  vals=(k['nama'].upper(),k['jenis_kelamin'],k['jabatan'],TINGKAT[k['tingkat']],k['wilayah'])
  for y,v in zip((141.22,133.89,126.37,119.62,112.87),vals):
   _fit(cv,': '+v,'Montserrat',5.5,118);cv.drawString(88.02,y,': '+v)
  cv.showPage()
 cv.save();return buf.getvalue()
