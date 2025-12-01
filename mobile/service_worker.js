// mobile/service_worker.js
const CACHE_NAME = "llaqta-v1";
const ASSETS = [
  "/",
  "/static/css/styles.css",
  "/static/js/main.js",
  "/static/img/llaqta_ultra.svg"
];

self.addEventListener("install", e=>{
  e.waitUntil(
    caches.open(CACHE_NAME).then(cache=>cache.addAll(ASSETS))
  );
});

self.addEventListener("fetch", e=>{
  e.respondWith(
    caches.match(e.request).then(r => r || fetch(e.request))
  );
});
