// static/js/mapa.js

// Inicializar mapa centrado en Huánuco
const map = L.map('map').setView([-9.93, -76.24], 13);

// Tiles OpenStreetMap
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19,
  attribution: '© OpenStreetMap'
}).addTo(map);

// Layer para marcadores
const markersLayer = L.layerGroup().addTo(map);

// Colores oficiales de categorías
const CATEGORY_COLORS = {
  "EMERGENCIA": "#e11d48",          // rojo intenso
  "APOYO_ADULTO_MAYOR": "#2563eb",  // azul
  "BULLYING": "#f59e0b",            // naranja
  "CLIMA": "#10b981",                // verde
  "OTRO": "#16a34a"                  // verde oscuro
};

// Crear marcador personalizado
function createMarker(lat, lng, category, desc, addr) {
  const color = CATEGORY_COLORS[category] || CATEGORY_COLORS["OTRO"];

  const icon = L.divIcon({
    className: "custom-marker",
    html: `<div style="
      width:20px;
      height:20px;
      background:${color};
      border-radius:50%;
      border:2px solid #fff;
      box-shadow:0 2px 6px rgba(0,0,0,0.3);
    "></div>`,
    iconSize: [24, 24],
    iconAnchor: [12, 12]
  });

  const marker = L.marker([lat, lng], { icon }).addTo(markersLayer);

  // Popup estilizado
  const popupContent = `
    <div style="font-family:Inter,sans-serif; font-size:14px;">
      <b style="color:${color}">${category.replace("_"," ")}</b><br>
      ${desc || ""}<br>
      <small style="color:#555">${addr || ""}</small>
    </div>
  `;
  marker.bindPopup(popupContent);
}

// Cargar alertas desde API
async function cargarAlertas() {
  try {
    const res = await fetch('/api/alertas');
    const list = await res.json();
    markersLayer.clearLayers();
    list.forEach(r => {
      if(r.lat && r.lng) createMarker(r.lat, r.lng, r.categoria, r.descripcion, r.direccion);
    });
  } catch(e) {
    console.error("Error cargando alertas", e);
  }
}

// Intervalo de actualización: cada 5 minutos
cargarAlertas();
setInterval(cargarAlertas, 300000);

// --- Leyenda en el mapa ---
const legend = L.control({position: 'bottomright'});

legend.onAdd = function(map){
  const div = L.DomUtil.create('div', 'legend');
  div.style.background = 'rgba(255,255,255,0.85)';
  div.style.padding = '10px 14px';
  div.style.borderRadius = '12px';
  div.style.boxShadow = '0 2px 8px rgba(0,0,0,0.15)';
  div.style.fontFamily = 'Inter, sans-serif';
  div.style.fontSize = '13px';
  
  div.innerHTML = '<b>Categorías</b><br>';
  for(const cat in CATEGORY_COLORS){
    div.innerHTML += `
      <div style="display:flex;align-items:center;margin-top:4px;">
        <span style="
          width:14px;
          height:14px;
          background:${CATEGORY_COLORS[cat]};
          display:inline-block;
          border-radius:50%;
          margin-right:6px;
        "></span>${cat.replace("_"," ")}
      </div>
    `;
  }
  return div;
};

legend.addTo(map);
