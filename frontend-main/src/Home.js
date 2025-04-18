import React, { useEffect, useState } from "react";
import { useKeycloak } from "@react-keycloak/web";

function Home() {
  // ดึง keycloak instance และ flag ที่บอกว่า initialize แล้ว
  const { keycloak, initialized } = useKeycloak();
  // สร้าง state เพื่อเก็บข้อมูล API ซึ่งเป็นอ็อบเจ็กต์
  const [apiData, setApiData] = useState(null);

  // useEffect สำหรับการเช็คการ authenticate
  useEffect(() => {
    if (initialized && !keycloak.authenticated) {
      keycloak.login();
    }
  }, [initialized, keycloak]);

  // ฟังก์ชันสำหรับดึงข้อมูลจาก API
  const fetchData = async () => {
    const response = await fetch("http://localhost:8081/api/data", {
      headers: {
        Authorization: `Bearer ${keycloak.token}`,
      },
    });
    const result = await response.json();
    // เก็บข้อมูลทั้งหมดที่ได้รับจาก API ใน state
    setApiData(result);
  };

  // ถ้ายังไม่ initialize ให้แสดง Loading...
  if (!initialized) {
    return <div>Loading...</div>;
  }

  return (
    <div style={{ padding: "20px" }}>
      {keycloak.authenticated ? (
        <>
          <h1>ยินดีต้อนรับ, {keycloak.tokenParsed?.preferred_username}</h1>
          <button onClick={fetchData}>เรียกข้อมูลจาก API</button>

          {/* ถ้ามีข้อมูลจาก API ให้แสดง key-value ทั้งหมด */}
          {apiData && (
            <div>
              <h2>ข้อมูลจาก API:</h2>
              {Object.entries(apiData).map(([key, value]) => (
                <p key={key}>
                  <strong>{key}:</strong> {JSON.stringify(value)}
                </p>
              ))}
            </div>
          )}

          <button onClick={() => keycloak.logout()}>ออกจากระบบ</button>
        </>
      ) : (
        <div>กำลังไปหน้า Login...</div>
      )}
    </div>
  );
}

export default Home;
