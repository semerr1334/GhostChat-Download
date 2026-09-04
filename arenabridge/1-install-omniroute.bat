@echo off
title Мост к Арене: шаг 1 — установка OmniRoute
echo ============================================
echo  Шаг 1 из 2: качаю установщик OmniRoute (500 МБ)
echo  Не закрывай окно, дождись установщика!
echo ============================================
echo.
powershell -NoProfile -Command "$u='https://github.com/diegosouzapw/OmniRoute/releases/download/v3.8.50/OmniRoute.Setup.3.8.50.exe'; $f=\"$env:TEMP\OmniRouteSetup.exe\"; Write-Host 'Качаю... это 500 МБ, терпение :)'; try { Invoke-WebRequest -Uri $u -OutFile $f -UseBasicParsing; Write-Host 'Скачал! Запускаю установщик...'; Start-Process $f } catch { Write-Host 'Авто-скачивание не вышло — открою страницу в браузере, качни файл OmniRoute.Setup.*.exe руками'; Start-Process 'https://github.com/diegosouzapw/OmniRoute/releases/latest' }"
echo.
echo Когда установка завершится — нажми любую кнопку тут.
echo Потом ЗАПУСТИ OmniRoute (ярлык на рабочем столе / в Пуске).
pause
