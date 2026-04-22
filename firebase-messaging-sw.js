importScripts('https://www.gstatic.com/firebasejs/8.10.1/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/8.10.1/firebase-messaging.js');

firebase.initializeApp({
    apiKey: "AIzaSyD9-X7wef2QRfT9Wvw3dbtrLl_n3pgosks",
    projectId: "tegeshka-a22b5",
    messagingSenderId: "467845350616",
    appId: "1:467845350616:web:e623bd9e2d679ebad543ad"
});

const messaging = firebase.messaging();

// Фоновая обработка клика по уведомлению
messaging.onBackgroundMessage(function(payload) {
    console.log('Получено фоновое сообщение:', payload);
    const notificationTitle = payload.notification.title;
    const notificationOptions = {
        body: payload.notification.body,
        icon: '/static/1.png',
        badge: '/static/1.png',
        data: payload.data
    };
    return self.registration.showNotification(notificationTitle, notificationOptions);
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close(); // Закрываем уведомление

    const room = event.notification.data.room;
    const targetUrl = room ? `/?room=${room}` : '/';

    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function(clientList) {
            // Если вкладка уже открыта, переключаемся на неё
            for (let client of clientList) {
                if (client.url.includes(targetUrl) && 'focus' in client) {
                    return client.focus();
                }
            }
            // Если нет — открываем новую
            if (clients.openWindow) {
                return clients.openWindow(targetUrl);
            }
        })
    );
});