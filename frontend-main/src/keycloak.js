import Keycloak from 'keycloak-js';

const keycloak = new Keycloak({
    url: 'http://localhost:8088', // URL ของ Keycloak
    realm: 'affiliate',
    clientId: 'affiliate',
    checkLoginIframe: false // ปิดการตรวจสอบ iframe เพื่อลดการใช้ Cookie
});

export default keycloak;
