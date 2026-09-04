# find_arena_cookie.py v2 — автопоиск куки Arena для OmniRoute 👻
# Читает куки arena.ai из Opera / Chrome / Edge / Brave / Vivaldi / Яндекс / Firefox.
# Всё происходит ТОЛЬКО на твоём ПК, ничего никуда не отправляется.
# Запуск: просто дважды кликни файл НАЙТИ-КУКИ.bat
#
# Для проверки самого себя (разработчик): python find_arena_cookie.py --selftest
import base64
import ctypes
import ctypes.wintypes as wt
import glob
import json
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

DOMAIN_PART = 'arena.ai'
MUST_NAMES = ('arena-auth-prod-v1.0', 'arena-auth-prod-v1.1')

# =====================================================================
# Мини-AES-256 (FIPS-197) + GCM (NIST SP 800-38D), чистый Python.
# Нужен, чтобы расшифровать куки Chromium-браузеров (Opera и др.):
# там значение = префикс "v10" + 12 байт nonce + AES-256-GCM(куки).
# =====================================================================

def _gf_mul8(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return r


def _make_sbox():
    # обратный элемент в GF(2^8) с полиномом 0x11B + аффинное преобразование
    def gmul(a, b):
        return _gf_mul8(a, b)

    def gpow(a, n):
        r = 1
        while n:
            if n & 1:
                r = gmul(r, a)
            a = gmul(a, a)
            n >>= 1
        return r

    sbox = []
    for i in range(256):
        inv = 0 if i == 0 else gpow(i, 254)
        s = inv
        for rot in (1, 2, 3, 4):
            s ^= ((inv << rot) | (inv >> (8 - rot))) & 0xFF
        sbox.append((s ^ 0x63) & 0xFF)
    return sbox


_SBOX = _make_sbox()


def _aes_expand_key(key):
    """AES-256 key expansion -> 15 раундовых ключей по 16 байт."""
    nk, nr = 8, 14
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]                      # RotWord
            temp = [_SBOX[b] for b in temp]                 # SubWord
            temp[0] ^= rcon
            rcon = _gf_mul8(rcon, 2)
        elif i % nk == 4:
            temp = [_SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[4 * r + c])
        round_keys.append(bytes(rk))
    return round_keys


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state):
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _shift_rows(state):
    # state[r + 4c]: строка r сдвигается влево на r
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            state[r + 4 * c] = row[c]


def _mix_columns(state):
    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        x0 = _gf_mul8(a0, 2)
        x1 = _gf_mul8(a1, 2)
        x2 = _gf_mul8(a2, 2)
        x3 = _gf_mul8(a3, 2)
        state[i]     = x0 ^ x1 ^ a1 ^ a2 ^ a3
        state[i + 1] = a0 ^ x1 ^ x2 ^ a2 ^ a3
        state[i + 2] = a0 ^ a1 ^ x2 ^ x3 ^ a3
        state[i + 3] = x0 ^ a0 ^ a1 ^ a2 ^ x3


def aes_encrypt_block(key, block):
    """Один блок AES-256 (16 байт)."""
    rks = _aes_expand_key(key)
    state = list(block)
    _add_round_key(state, rks[0])
    for rnd in range(1, 14):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, rks[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, rks[14])
    return bytes(state)


def _gcm_mul(x, y):
    """Умножение в GF(2^128) для GHASH."""
    R = 0xE1000000000000000000000000000000
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if (v & 1) else (v >> 1)
    return z


def _ghash(h, data):
    y = 0
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        if len(block) < 16:
            block = block + b'\x00' * (16 - len(block))
        y = _gcm_mul(y ^ int.from_bytes(block, 'big'), h)
    return y


def _gctr(key, icb, data):
    out = bytearray()
    ctr = icb
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        ks = aes_encrypt_block(key, ctr.to_bytes(16, 'big'))
        out.extend(bytes(a ^ b for a, b in zip(chunk, ks)))
        ctr = (ctr & ~(0xFFFFFFFF)) | ((ctr + 1) & 0xFFFFFFFF)
    return bytes(out)


def aes_gcm_decrypt(key, nonce, ct_and_tag, aad=b''):
    """Расшифровка AES-256-GCM. nonce — 12 байт. Возвращает bytes или None при битом теге."""
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    j0 = int.from_bytes(nonce, 'big') << 32 | 1
    h = int.from_bytes(aes_encrypt_block(key, b'\x00' * 16), 'big')
    s = _ghash(h, aad + b'\x00' * ((16 - len(aad) % 16) % 16) +
               ct + b'\x00' * ((16 - len(ct) % 16) % 16) +
               struct.pack('>QQ', len(aad) * 8, len(ct) * 8))
    t = s ^ int.from_bytes(_gctr(key, j0, b'\x00' * 16), 'big')
    if t != int.from_bytes(tag, 'big'):
        return None
    return _gctr(key, (j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF), ct)


def aes_gcm_encrypt(key, nonce, pt, aad=b''):
    """Шифрование AES-256-GCM (нужно для самотеста)."""
    j0 = int.from_bytes(nonce, 'big') << 32 | 1
    h = int.from_bytes(aes_encrypt_block(key, b'\x00' * 16), 'big')
    ct = _gctr(key, (j0 & ~0xFFFFFFFF) | ((j0 + 1) & 0xFFFFFFFF), pt)
    s = _ghash(h, aad + b'\x00' * ((16 - len(aad) % 16) % 16) +
               ct + b'\x00' * ((16 - len(ct) % 16) % 16) +
               struct.pack('>QQ', len(aad) * 8, len(ct) * 8))
    t = s ^ int.from_bytes(_gctr(key, j0, b'\x00' * 16), 'big')
    return ct + t.to_bytes(16, 'big')


# =====================================================================
# Windows DPAPI — расшифровка мастер-ключа Chromium (работает только
# на твоём ПК под твоим пользователем, куда-либо данные не уходят).
# =====================================================================

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wt.DWORD), ('pbData', ctypes.POINTER(ctypes.c_char))]


def dpapi_decrypt(data):
    if os.name != 'nt':
        return None
    blob_in = _DATA_BLOB(len(data), ctypes.cast(
        ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    try:
        ok = ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
        if not ok:
            return None
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    except Exception:
        return None
    finally:
        if blob_out.pbData:
            ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def chromium_master_key(local_state_path):
    """Читаем Local State -> os_crypt.encrypted_key -> DPAPI -> AES-ключ."""
    try:
        with open(local_state_path, 'r', encoding='utf-8') as f:
            ls = json.load(f)
        enc = base64.b64decode(ls['os_crypt']['encrypted_key'])
        if enc[:5] == b'DPAPI':
            enc = enc[5:]
        return dpapi_decrypt(enc)
    except Exception:
        return None


def decrypt_chromium_value(enc_key, raw):
    """Расшифровка одного значения куки Chromium."""
    if not raw:
        return None
    try:
        if raw[:3] in (b'v10', b'v11'):
            if enc_key is None:
                return None
            nonce, blob = raw[3:15], raw[15:]
            pt = aes_gcm_decrypt(enc_key, nonce, blob)
            return pt.decode('utf-8', 'strict') if pt else None
        # очень старый формат — чистый DPAPI
        pt = dpapi_decrypt(raw)
        return pt.decode('utf-8', 'strict') if pt else None
    except Exception:
        return None


# =====================================================================
# Поиск браузеров и чтение баз куки
# =====================================================================

def chromium_browsers():
    """(имя, путь к Local State, шаблон поиска файла Cookies)"""
    la = os.environ.get('LOCALAPPDATA', '')
    ra = os.environ.get('APPDATA', '')
    lst = [
        ('Opera',         os.path.join(ra, 'Opera Software', 'Opera Stable')),
        ('Opera GX',      os.path.join(ra, 'Opera Software', 'Opera GX Stable')),
        ('Google Chrome', os.path.join(la, 'Google', 'Chrome', 'User Data')),
        ('Microsoft Edge', os.path.join(la, 'Microsoft', 'Edge', 'User Data')),
        ('Brave',         os.path.join(la, 'BraveSoftware', 'Brave-Browser', 'User Data')),
        ('Vivaldi',       os.path.join(la, 'Vivaldi', 'User Data')),
        ('Yandex Browser', os.path.join(la, 'Yandex', 'YandexBrowser', 'User Data')),
    ]
    out = []
    for name, root in lst:
        if root and os.path.isdir(root):
            out.append((name, root))
    return out


def find_cookie_files(root):
    """Все файлы Cookies в профилях браузера (глубина до 3)."""
    pats = [
        os.path.join(root, 'Network', 'Cookies'),
        os.path.join(root, 'Default', 'Network', 'Cookies'),
        os.path.join(root, 'Profile *', 'Network', 'Cookies'),
        os.path.join(root, 'Cookies'),
    ]
    found = []
    for p in pats:
        found.extend(f for f in glob.glob(p) if os.path.isfile(f))
    # свежие первыми
    return sorted(set(found), key=os.path.getmtime, reverse=True)


def copy_db_locked(path, tag):
    """Копируем базу + WAL/SHM, т.к. браузер держит её открытой."""
    tmpdir = tempfile.gettempdir()
    dst = os.path.join(tmpdir, f'ck_{tag}.sqlite')
    for src, suf in ((path, ''), (path + '-wal', '-wal'), (path + '-shm', '-shm')):
        if os.path.isfile(src):
            try:
                shutil.copyfile(src, dst + suf)
            except OSError:
                pass
    return dst if os.path.isfile(dst) else None


def arena_cookies_from_chromium_db(enc_key, db_path):
    db = copy_db_locked(db_path, str(abs(hash(db_path))))
    if not db:
        return {}
    cookies = {}
    try:
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute(
                "SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE ?",
                ('%' + DOMAIN_PART + '%',))
            rows = cur.fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        rows = []
    for name, value, enc in rows:
        if name in cookies:
            continue
        if enc:
            v = decrypt_chromium_value(enc_key, enc)
        elif value:
            v = value
        else:
            v = None
        if v:
            cookies[name] = v
    for suf in ('', '-wal', '-shm'):
        try:
            os.remove(db + suf)
        except OSError:
            pass
    return cookies


def arena_cookies_from_firefox():
    base = os.environ.get('APPDATA', '')
    found = glob.glob(os.path.join(base, 'Mozilla', 'Firefox', 'Profiles', '*', 'cookies.sqlite'))
    found = [f for f in found if os.path.isfile(f)]
    if not found:
        return None, {}
    db_path = max(found, key=os.path.getmtime)
    db = copy_db_locked(db_path, 'ff')
    cookies = {}
    try:
        con = sqlite3.connect(db)
        try:
            cur = con.cursor()
            cur.execute(
                "SELECT name, value FROM moz_cookies WHERE host LIKE ? ORDER BY creationTime DESC",
                ('%' + DOMAIN_PART + '%',))
            rows = cur.fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        rows = []
    for name, value in rows:
        if name not in cookies:
            cookies[name] = value
    for suf in ('', '-wal', '-shm'):
        try:
            os.remove(db + suf)
        except OSError:
            pass
    return db_path, cookies


def to_clipboard(text):
    try:
        p = subprocess.Popen('clip', stdin=subprocess.PIPE, shell=True)
        p.communicate(text.encode('utf-8', 'ignore'))
        return p.returncode == 0
    except Exception:
        return False


def collect_all():
    """Сканируем все браузеры. Возвращаем список (браузер, {куки})."""
    results = []
    for name, root in chromium_browsers():
        key = chromium_master_key(os.path.join(root, 'Local State'))
        for db in find_cookie_files(root):
            ck = arena_cookies_from_chromium_db(key, db)
            if ck:
                results.append((name, ck))
                break
    _db, ffc = arena_cookies_from_firefox()
    if ffc:
        results.append(('Firefox', ffc))
    return results


def main():
    print('=' * 60)
    print('  👻 Автопоиск куки Arena для OmniRoute v2')
    print('  (Opera / Chrome / Edge / Brave / Vivaldi / Yandex / Firefox)')
    print('=' * 60)
    results = collect_all()
    if not results:
        print('\n❌ Куки arena.ai не найдены ни в одном браузере.')
        print('   1) Открой в браузере (например, Opera) сайт arena.ai')
        print('   2) ВОЙДИ в свой аккаунт (обязательно дойди до чата)')
        print('   3) Запусти эту программу снова')
        input('\nНажми Enter для выхода...')
        sys.exit(1)
    # приоритет: где найдены оба нужных куки, иначе — Opera, иначе — первый
    def score(item):
        name, ck = item
        have = sum(1 for n in MUST_NAMES if n in ck)
        return (have, 1 if name.startswith('Opera') else 0, len(ck))
    results.sort(key=score, reverse=True)
    browser, cookies = results[0]
    names = sorted(cookies.keys())
    missing = [n for n in MUST_NAMES if n not in cookies]
    header = '; '.join(f'{n}={cookies[n]}' for n in names)
    out_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'arena_cookie.txt')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(header)
    ok = to_clipboard(header)
    print(f'\n✅ Куки arena.ai найдены в браузере: {browser} ({len(names)} шт.)')
    if len(results) > 1:
        print('   (также найдены в: ' + ', '.join(n for n, _ in results[1:]) + ')')
    for n in names:
        print('   •', n, ('⬅ нужный!' if n in MUST_NAMES else ''))
    if missing:
        print('\n⚠️ Не хватает: ' + ', '.join(missing))
        print('   Открой arena.ai в этом браузере, перелогинься и запусти снова.')
    else:
        print('\n🎉 Оба нужных куки на месте!')
    print('\n📋 Заголовок Cookie готов:')
    print('   • сохранён в файл: ' + out_path)
    print('   • ' + ('уже в БУФЕРЕ ОБМЕНА — жми Ctrl+V в OmniRoute! 📋'
                         if ok else 'скопируй его из файла arena_cookie.txt'))
    print('\n⚠️ НЕ выходи из аккаунта в браузере — иначе сессия умрёт.')
    print('🔒 Никому не показывай этот текст — это как пароль!')
    input('\nНажми Enter для выхода...')


def selftest():
    """Проверка AES/GCM на эталонных векторах + круговой тест с sqlite."""
    print('🔬 Self-test...')
    # 1) AES-256 из FIPS-197: ключ 0, блок 0
    c = aes_encrypt_block(bytes(32), bytes(16))
    assert c.hex() == 'dc95c078a2408989ad48a21492842087', c.hex()
    print('   ✅ AES-256 block vector OK')
    # 2) AES-256-GCM, NIST vector: ключ 0, IV 0, P = 16 нулей
    enc = aes_gcm_encrypt(bytes(32), bytes(12), bytes(16))
    assert enc.hex() == 'cea7403d4d606b6e074ec5d3baf39d18' + 'd0d1c8a799996bf0265b98b5d48ab919', enc.hex()
    print('   ✅ AES-256-GCM NIST vector OK')
    # 3) круговой тест со случайными данными + AAD
    key = bytes(range(32))
    nonce = bytes(range(12))
    pt = ('session=very-secret-token-value-12345; path=/').encode()
    blob = aes_gcm_encrypt(key, nonce, pt)
    dec = aes_gcm_decrypt(key, nonce, blob)
    assert dec == pt, dec
    # битый тег должен дать None
    bad = bytearray(blob); bad[-1] ^= 1
    assert aes_gcm_decrypt(key, nonce, bytes(bad)) is None
    print('   ✅ round-trip + tamper check OK')
    # 4) v10-блоб как у Chromium + sqlite-база
    raw = b'v10' + nonce + blob
    assert decrypt_chromium_value(key, raw) == pt.decode()
    tmp = os.path.join(tempfile.gettempdir(), 'ck_fake_cookies.sqlite')
    if os.path.exists(tmp):
        os.remove(tmp)
    con = sqlite3.connect(tmp)
    con.execute('CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB)')
    con.execute('INSERT INTO cookies VALUES (?,?,?,?)',
                ('.arena.ai', 'arena-auth-prod-v1.0', '', sqlite3.Binary(raw)))
    con.commit(); con.close()
    ck = arena_cookies_from_chromium_db(key, tmp)
    assert ck.get('arena-auth-prod-v1.0') == pt.decode(), ck
    os.remove(tmp)
    print('   ✅ chromium-style db + v10 blob OK')
    print('🎉 Все тесты пройдены!')


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        selftest()
    else:
        main()
