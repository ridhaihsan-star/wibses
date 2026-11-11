"""Launcher lokal WIB–SES Group. Tidak membuka akses jaringan publik."""
import os,socket,sys,threading,time,webbrowser
from pathlib import Path
BASE=Path(__file__).resolve().parent
mode=(sys.argv[1].lower() if len(sys.argv)>1 else 'operasional')
lan=len(sys.argv)>2 and sys.argv[2].lower()=='lan'
if mode not in ('demo','operasional') or (len(sys.argv)>2 and not lan):
 print('Gunakan: python launcher.py demo | operasional [lan]');raise SystemExit(2)
def lan_ip():
 try:
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   s.connect(('10.255.255.255',1));return s.getsockname()[0]
 except Exception:return '127.0.0.1'
store=BASE/('data_demo' if mode=='demo' else 'data_operasional')
store.mkdir(exist_ok=True)
first_launch=not (store/'wib_ses.sqlite3').exists()
os.environ['WIB_DATA_DIR']=str(store)
os.environ['WIB_SEED_DEMO']='1' if mode=='demo' else '0'
import app
if first_launch and mode=='operasional':
 source=BASE/'import_sumber'/'Data_Kepengurusan_WIB_2026.xlsx'
 if source.exists():
  try:
   with app.db() as connection:
    admin=app.row(connection,"SELECT id FROM users WHERE username='admin'")
   result=app.stage_excel_bytes(source.read_bytes(),admin['id'])
   print(f" Data awal dimasukkan: {result['created']} posisi draft, {result['blank']} posisi belum terisi.")
  except Exception as e:
   print(' Impor otomatis gagal; gunakan menu Data Pengurus > Impor Excel:',e)
url='http://127.0.0.1:8765/'
print('\n'+'='*62)
print(' WIB x SES GROUP — SISTEM INFORMASI TERPADU')
print(' Mode:',mode.upper(),'| Alamat:',url)
if lan:
 print(' AKSES LAN AKTIF. Komputer lain di jaringan yang sama buka:')
 print(f'   http://{lan_ip()}:8765/')
 print(' Koneksi HTTP tanpa enkripsi: pakai hanya di jaringan kantor tertutup.')
print(' Database:',app.DB)
print(' Akun awal:',store/'AKUN_AWAL_RAHASIA.txt')
print(' Akun dibuat sekali saat database pertama kali dibangun.')
print(' Segera ubah kata sandi dari menu PENGATURAN setelah login.')
print(' Tekan CTRL+C untuk menghentikan aplikasi.')
print('='*62+'\n')
def show():
 time.sleep(2)
 try:webbrowser.open(url)
 except Exception:pass
threading.Thread(target=show,daemon=True).start()
import uvicorn
uvicorn.run(app.app,host='0.0.0.0' if lan else '127.0.0.1',port=8765,log_level='warning')
