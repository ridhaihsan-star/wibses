"""SK SES Group: Koordinator Wilayah (Ketua DPW, template SK KEPALA KANWIL), Kepala Cabang (Ketua DPD/DPC,
SK KEPALA KANCAB), dan Kepala Unit (Ketua PAC, SK KEPALA KANTOR UNIT): kode wilayah SES, nomor SK, isian template Word.

Kode wilayah SES (referensi/kode_wilayah_ses.json, dari Table Wilayah SES Group.xlsx) berbeda urutan dengan
kode WIB, jadi setiap kab/kota SES menyimpan pasangan kode WIB-nya (`wib_kode`) untuk menautkan pengurus WIB."""
import io, json, re
from pathlib import Path
import openpyxl
import sk_wib

BASE = Path(__file__).resolve().parent
REF = json.loads((BASE / 'referensi' / 'kode_wilayah_ses.json').read_text(encoding='utf-8'))
ROLE = 'Kepala Cabang'
ROLE_WIL = 'Koordinator Wilayah'  # isi SK (template KANWIL) menyebut "Kepala Wilayah"
ROLE_UNIT = 'Kepala Unit'
ROLES = (ROLE_WIL, ROLE, ROLE_UNIT)
ROLE_LEVELS = {ROLE_WIL: ('DPW',), ROLE: ('DPD', 'DPC'), ROLE_UNIT: ('PAC',)}
LEVEL_ROLE = {lv: r for r, lvs in ROLE_LEVELS.items() for lv in lvs}
TEMPLATE = {ROLE_WIL: 'template_sk_ses_wilayah.docx', ROLE: 'template_sk_ses.docx', ROLE_UNIT: 'template_sk_ses_unit.docx'}
LEVELS = ROLE_LEVELS[ROLE]  # Kepala Cabang SES = pengurus WIB tingkat kabupaten (DPD) / kota (DPC)
FIELDS_REQUIRED = {'NOMOR_SK', 'NAMA', 'WILAYAH', 'TANGGAL_TEKS'}

_PROV_BY_WIB = {p['wib_kode']: p for p in REF['provinsi'] if p.get('wib_kode')}
_BY_WIB = {(p['wib_kode'], w['wib_kode']): (p, w) for p in REF['provinsi'] for w in p['wilayah'] if p.get('wib_kode') and w.get('wib_kode')}

def province(code): return next((p for p in REF['provinsi'] if p['kode'] == code), None)
def region(prov, code): return next((w for w in prov['wilayah'] if w['kode'] == code), None) if prov else None

def resolve(a):
    """(provinsi SES, kab/kota SES) untuk penugasan/jabatan `a`. Kode SES yang tersimpan didahulukan,
    selain itu diturunkan dari kode wilayah WIB jabatan tersebut."""
    if a.get('ses_prov_code'):
        p = province(a['ses_prov_code'])
        return p, region(p, a.get('ses_city_code'))
    if a.get('level') not in LEVEL_ROLE: return None, None
    wp, wr = sk_wib.resolve_codes(a)
    if a['level'] == 'DPW': return _PROV_BY_WIB.get(wp['kode'] if wp else None), None
    return _BY_WIB.get((wp['kode'] if wp else None, wr['kode'] if wr else None), (None, None))

def unit_code(v):
    """Nomor unit diketik admin: 1-3 angka, ditulis minimal 2 digit (3 -> 03)."""
    v = str(v or '').strip()
    return v.zfill(2) if re.fullmatch(r'\d{1,3}', v) and int(v) > 0 else None

def unit_name(district, w):
    """Nama unit di SK Kepala Unit: kecamatan (dari jabatan PAC) + kab/kota SES."""
    d = re.sub(r'^(KECAMATAN|KEC\.?|DISTRIK)\s+', '', ' '.join(str(district or '').split()), flags=re.I)
    if not d or not w: return None
    jenis = 'Distrik' if re.match(r'\s*distrik\b', str(district), re.I) else 'Kecamatan'
    return f"{jenis} {' '.join(x.capitalize() for x in d.split())}, {w['tampil']}"

def code(role, p, w, unit=None):
    if not p: return ''
    if role == ROLE_WIL: return p['kode']
    if not w: return ''
    return f"{p['kode']}-{w['kode']}" + (f'.01.{unit}' if role == ROLE_UNIT and unit else '')

def label(p, w): return f"{p['kode']}-{w['kode']} · {w['tampil']}" if p and w else ''

def number(role, p, w, when, unit=None):
    """KANWIL PP-01, KANCAB PP-KK.01, KANTOR UNIT PP-KK.01.UU; lalu /SES-GROUP/bulan Romawi/tahun."""
    head = f"{p['kode']}-01" if role == ROLE_WIL else f"{p['kode']}-{w['kode']}.01" + (f'.{unit}' if role == ROLE_UNIT else '')
    return f"{head}/SES-GROUP/{sk_wib.ROMAWI[when.month - 1]}/{when.year}"

def values(nomor, person, wilayah, when):
    """Isian merge field template SK SES; `wilayah` = provinsi (KANWIL), kab/kota (KANCAB), atau nama unit."""
    return {'NOMOR_SK': nomor, 'SAPAAN': 'Sdri.' if str(person.get('gender') or '').lower().startswith('p') else 'Sdr.',
            'NAMA': person['full_name'].upper().strip(), 'WILAYAH': wilayah, 'WILAYAH_BESAR': wilayah.upper(),
            'TANGGAL_TEKS': sk_wib.tanggal_teks(when)}

def name_key(s): return re.sub(r'[^A-Z0-9]', '', str(s or '').upper())

def read_table(data):
    """Baca sheet KAB KOTA Table Wilayah SES Group.xlsx -> [{_row, prov, kode, wilayah, nama, tanggal, nomor}] untuk
    baris yang kolom NAMA-nya terisi. Kolom TANGGAL dan NOMOR_SK opsional. None bila bukan file tabel wilayah SES."""
    wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    ws = next((s for s in wb.worksheets if s.title.strip().upper().replace('/', ' ') in ('KAB KOTA', 'KABKOTA', 'KAB  KOTA')), None)
    if ws is None: return None
    head = None; out = []
    for i, r in enumerate(ws.iter_rows(values_only=True), 1):
        cells = [sk_wib._cell(v).upper() for v in r]
        if head is None:
            if 'NO WILAYAH' in cells and 'NO DAERAH' in cells and 'NAMA' in cells:
                head = {k: cells.index(k) for k in ('NO WILAYAH', 'NO DAERAH', 'NAMA')}
                head['WIL'] = next((j for j, c in enumerate(cells) if c.replace(' ', '') == 'KABUPATEN/KOTA'), None)
                head['TANGGAL'] = next((j for j, c in enumerate(cells) if c.replace('_', ' ') in ('TANGGAL', 'TANGGAL SK')), None)
                head['NOMOR'] = next((j for j, c in enumerate(cells) if c.replace('_', ' ') in ('NOMOR SK', 'NO SK', 'NOMOR')), None)
                head['TANGGAL'] = next((j for j, c in enumerate(cells) if c.replace('_', ' ') in ('TANGGAL', 'TANGGAL SK')), None)
                head['NOMOR'] = next((j for j, c in enumerate(cells) if c.replace('_', ' ') in ('NOMOR SK', 'NO SK', 'NOMOR')), None)
                head['TANGGAL'] = next((j for j, c in enumerate(cells) if c.replace('_', ' ') in ('TANGGAL', 'TANGGAL SK')), None)
                head['NOMOR'] = next((j for j, c in enumerate(cells) if c.replace('_', ' ') in ('NOMOR SK', 'NO SK', 'NOMOR')), None)
            continue
        get = lambda k: r[head[k]] if head[k] is not None and head[k] < len(r) else None
        pw, dw, nama = get('NO WILAYAH'), get('NO DAERAH'), sk_wib._cell(get('NAMA'))
        if not (isinstance(pw, (int, float)) and isinstance(dw, (int, float))) or not nama: continue
        tgl, tgl_teks = sk_wib.parse_tanggal(get('TANGGAL'))
        out.append({'_row': i, 'prov': f'{int(pw):02d}', 'kode': f'{int(dw):02d}', 'wilayah': sk_wib._cell(get('WIL')), 'nama': re.sub(r'\s+', ' ', nama),
                    'tanggal': tgl, 'tanggal_teks': tgl_teks, 'nomor': sk_wib._cell(get('NOMOR'))})
    return out if head else None
