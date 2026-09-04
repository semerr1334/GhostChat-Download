@echo off
title Мост к Арене: проверка связи
echo ============================================
echo  Проверяю, отвечает ли OmniRoute на localhost:20128
echo ============================================
echo.
powershell -NoProfile -Command "try { $r = Invoke-RestMethod 'http://localhost:20128/v1/models' -TimeoutSec 6; Write-Host ('ВСЁ ЖИВО! Моделей видно: ' + $r.data.Count) } catch { Write-Host ('OmniRoute не отвечает: ' + $_.Exception.Message); Write-Host 'ОТКРОЙ приложение OmniRoute (значок возле часов) и повтори.' }"
echo.
pause
