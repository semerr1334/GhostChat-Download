@echo off
title Мост к Арене: запуск агента
echo ============================================
echo  Запуск Claude Code ЧЕРЕЗ OmniRoute (модели Arena)
echo  Важно: OmniRoute должен быть включён!
echo ============================================
echo.
set "KEY=sk-local"
set /p "KEY=1) Вставь API-ключ из OmniRoute (Dashboard - API Keys) [Enter = sk-local]: "
set "MODEL=auto/coding"
set /p "MODEL=2) Модель [Enter = auto/coding, сам выберет лучшую рабочую]: "
set "ANTHROPIC_BASE_URL=http://localhost:20128"
set "ANTHROPIC_AUTH_TOKEN=%KEY%"
set "ANTHROPIC_MODEL=%MODEL%"
echo.
echo Запускаю! base=%ANTHROPIC_BASE_URL% model=%ANTHROPIC_MODEL%
echo Пиши приказы прямо тут. Выход из Клода: два раза Ctrl+C
echo.
call claude %*
pause
