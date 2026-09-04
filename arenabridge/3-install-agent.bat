@echo off
title Мост к Арене: ставлю агента Claude Code
echo ============================================
echo  Ставлю агента Claude Code (ОН ДЕЛАЕТ ДЕЛА, не болтает)
echo ============================================
echo.
where node >nul 2>nul
if errorlevel 1 (
  echo Нужен Node.js! Открываю страницу загрузки:
  echo качай кнопкой LTS, ставь всё по умолчанию (Next - Next - Finish),
  echo потом запусти этот файл ЕЩЁ РАЗ.
  start https://nodejs.org/ru/download
  pause
  exit /b 1
)
echo Node.js на месте. Ставлю Claude Code...
call npm i -g @anthropic-ai/claude-code
echo.
echo Готово! Теперь запускай агента через 4-run-agent.bat
pause
