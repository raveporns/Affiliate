import React, { useEffect, useState } from "react";
import { useKeycloak } from "@react-keycloak/web";
import "../css/homepage.css";
import Header from "../component/header";

function Homepage() {
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
    <div className="bg-homepage">
      {/* <Header /> */}
      {keycloak.authenticated ? (
        <>
          <div className="container">
            <div className="row" id="row-container">
              <div className="col-4" id="left">
                <div className="square-logo">
                  <h2>JOBJAB group</h2>
                </div>
                <div className="btn">
                    <p>Dashborad</p>
                </div>
                <div className="btn">
                    <p>ข้อมูลที่นำไปแสดงได้</p>
                </div>
                <div className="btn">
                    <p>ตัวอย่างหน้าที่ได้</p>
                </div>
              </div>
              <div className="col-8" id="right">
                <Header/>
                <h1>
                  ยินดีต้อนรับ, {keycloak.tokenParsed?.preferred_username}
                </h1>
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
              </div>
            </div>
          </div>
        </>
      ) : (
        <div>กำลังไปหน้า Login...</div>
      )}
    </div>
  );
}

export default Homepage;
