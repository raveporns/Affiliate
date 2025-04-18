import React from "react";
import "../css/header.css";
import { useKeycloak } from "@react-keycloak/web";

function Header() {
      const { keycloak, initialized } = useKeycloak();
    
  return (
    <div>
      <div className="bar">
      <button onClick={() => keycloak.logout()}>ออกจากระบบ</button>
      </div>
    </div>
  );
}

export default Header;
