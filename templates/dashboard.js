// SocketIO connection
const socket = io("/dashboard");

// ------------- Real-Time Anomaly Events -------------
socket.on("new_event", evt => {
    addEvent(evt);  // ⬅ SHOWS IN THREAT UI
});


// Receive initial batch
socket.on("init", list => {
    list.forEach(addEventRow);
});

// Add event row to table
function addEventRow(evt) {
    const table = document.getElementById("eventTable");
    const row = table.insertRow(1);
    row.innerHTML = `
        <td>${evt.iso_time}</td>
        <td>${evt.reconstruction_error.toFixed(4)}</td>
        <td>${evt.anomaly ? "⚠ HIGH RISK" : "Safe"}</td>
    `;
}
function addEvent(e){
    let cls = e.anomaly ? "risk" : "safe";

    document.getElementById("threat-feed").innerHTML =
    `<div class="event-card ${cls}">
        <b>${e.iso_time}</b><br>
        Threat: ${e.anomaly ? "⚠ HIGH RISK" : "🟢 SAFE"}<br>
        Error Score: ${e.reconstruction_error.toFixed(4)}
    </div>` + document.getElementById("threat-feed").innerHTML;
}

// ------------- WiFi Scanner -------------
// ================= WIFI SCANNER UI FIX =====================
function scanWiFi(){
    document.getElementById("wifi").innerHTML = "Scanning...";
    
    fetch("/wifi-scan")
    .then(r=>r.json())
    .then(d=>{
        if (!d.results || d.results.length === 0){
            document.getElementById("wifi").innerHTML = `
                <div style="padding:10px;color:#ff6b6b;">
                    ⚠ No networks detected — wifi scanner returned empty.
                </div>
            `;
            return;
        }

        let table = `
        <table>
            <tr><th>SSID</th><th>Security</th><th>Risk</th></tr>
        `;

        d.results.forEach(n=>{
            let risk = n.security.includes("WPA3") ? "Low" :
                       n.security.includes("WPA2") ? "Medium" : "⚠ High";

            table += `
                <tr>
                    <td>${n.ssid || "Unknown"}</td>
                    <td>${n.security}</td>
                    <td style="color:${risk==="⚠ High"?"#ff4d4d":"#4dff88"}">${risk}</td>
                </tr>
            `;
        });

        table += "</table>";
        document.getElementById("wifi").innerHTML = table;
    })
    .catch(e=>{
        document.getElementById("wifi").innerHTML =
        `<span style="color:#ff4d4d;">ERROR: ${e}</span>`;
    });
}

// ------------- Vault Load -------------
async function loadVault() {
    let res = await fetch("/vault-list");   // API you already have
    let data = await res.json();

    document.getElementById("vault_status").innerText =
        `${data.length} stored accounts`;

    const table = document.getElementById("vaultTable");
    table.innerHTML = "<tr><th>Service</th><th>Username</th><th>Breach?</th><th>Count</th></tr>";

    data.forEach(v => {
        let row = table.insertRow();
        row.innerHTML = `
            <td>${v.service}</td>
            <td>${v.username}</td>
            <td>${v.pwned ? "⚠ YES" : "Safe"}</td>
            <td>${v.pwned_count}</td>
        `;
    });
}
async function loadThreatFeed() {
    const container = document.getElementById("threat-feed");

    try {
        const res = await fetch("/events");
        const data = await res.json();

        container.innerHTML = ""; // clear before redraw

        data.reverse().forEach(event => {
            const item = document.createElement("div");
            item.className = "threat-card";

            item.innerHTML = `
                <p><strong>🧠 ${event.anomaly ? "Threat Detected" : "Normal Behaviour"}</strong></p>
                <p><b>Time:</b> ${event.iso_time}</p>
                <p><b>Error:</b> ${event.reconstruction_error.toFixed(3)}</p>
                <p><b>Threshold:</b> ${event.threshold.toFixed(3)}</p>
                <p><b>Connections:</b> ${event.input.conn_count}</p>
                <p><b>CPU:</b> ${event.input.cpu_pct}%</p>
                <p><b>Battery Drain:</b> ${event.input.battery_drain}%/min</p>
            `;

            container.appendChild(item);
        });

    } catch (e) {
        console.error("Threat feed failed:", e);
    }
}

// refresh every 3 seconds
setInterval(loadThreatFeed, 3000);
loadThreatFeed(); // initial load

// Load WiFi + Vault on startup
scanWifi();
loadVault();
