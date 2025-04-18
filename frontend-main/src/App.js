import React from 'react';
import { ReactKeycloakProvider } from '@react-keycloak/web';
import keycloak from './keycloak';
import Home from './Home';
import Homepage from './pages/homepage'
import 'bootstrap/dist/css/bootstrap.min.css';

function App() {
  const handleOnEvent = (event, error) => {
    console.log('onKeycloakEvent', event, error);
  };

  const loadingComponent = <div>กำลังโหลด Keycloak...</div>;

  return (
    <ReactKeycloakProvider
      authClient={keycloak}
      onEvent={handleOnEvent}
      LoadingComponent={loadingComponent}
      initOptions={{
        checkLoginIframe: false,
        onLoad: 'check-sso',
        redirectUri: 'http://localhost:3000/', 
        pkceMethod: 'S256' 
      }}
    >
      <Homepage />
    </ReactKeycloakProvider>
  );
}

export default App;