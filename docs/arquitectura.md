# Arquitectura LlaqtaShield

Breve:
- Frontend: templates + static (Leaflet)
- Backend: Flask Python (app.py)
- DB: SQLite (llaqta.db)
- PWA: mobile/manifest.json + service_worker.js
- Reportes: generados como HTML en /reportes_generados

Flujo:
1. Usuario envía formulario en /reportar
2. Backend guarda en DB (/report)
3. Backend genera documento HTML en /reportes_generados
4. Admin revisa desde /admin/reports
