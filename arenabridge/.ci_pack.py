#!/usr/bin/env python3
# Упаковщик пакета «Мост к Арене» (запускается в CI).
# Батники -> CP866 (для русской консоли), инструкция -> UTF-8 с BOM (для Блокнота).
import io
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
DST = os.path.join('pkg', 'ArenaBridge')

os.makedirs(DST, exist_ok=True)


def sane(t):
    # cp866 старая: без тире-строколомов и эмодзи — аккуратно заменяем
    t = (t.replace('—', '-').replace('–', '-').replace('…', '...')
         .replace('→', '->').replace('🌉', '').replace('👻', '<G>')
         .replace('🎉', ':)').replace('🔥', '!!').replace('🎰', ''))
    return t.encode('cp866', errors='replace').decode('cp866')


for name in ('1-install-omniroute.bat', '2-find-cookie.bat', '3-install-agent.bat',
             '4-run-agent.bat', '5-test.bat'):
    with io.open(os.path.join(HERE, name), encoding='utf-8') as f:
        text = sane(f.read())
    with io.open(os.path.join(DST, name), 'w', encoding='cp866', newline='\r\n') as f:
        f.write(text)
    print('bat ->cp866:', name)

with io.open(os.path.join(HERE, 'ИНСТРУКЦИЯ.txt'), encoding='utf-8') as f:
    instr = f.read()
with io.open(os.path.join(DST, 'ИНСТРУКЦИЯ.txt'), 'w', encoding='utf-8-sig', newline='\r\n') as f:
    f.write(instr)
print('instrukcia ->utf8bom')

exe_src = os.path.join('dist', 'find-cookie.exe')
assert os.path.exists(exe_src), 'pyinstaller exe не найден: ' + exe_src
shutil.copy(exe_src, os.path.join(DST, 'find-cookie.exe'))
print('exe ok')

print('PACKED ->', DST, os.listdir(DST))
