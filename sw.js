self.addEventListener("install",()=>self.skipWaiting());
self.addEventListener("fetch",()=>{});
self.addEventListener("push",e=>{let d={};try{d=e.data.json()}catch(_){}e.waitUntil(self.registration.showNotification(d.title||"Lémou et Touty",{body:d.body||"",icon:"logo-192.png",badge:"logo-192.png"}))});
self.addEventListener("notificationclick",e=>{e.notification.close();e.waitUntil(clients.openWindow("/"))});
