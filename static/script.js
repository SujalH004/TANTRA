// static/script.js
document.addEventListener("DOMContentLoaded", () => {
    const socket = io();

    let operativeCallsign = "";
    let comsecKey = "";
    let bootTime = Date.now();
    let knownPeers = new Set();
    let topologyDetails = {};

    // DOM References matching index.html
    const gatewayZone = document.getElementById("gateway-zone");
    const commandZone = document.getElementById("command-zone");
    const inputCallsign = document.getElementById("callsign");
    const inputMasterKey = document.getElementById("master-key");
    const btnLogin = document.getElementById("btn-login");

    const navCallsign = document.getElementById("nav-callsign");
    const btnStealth = document.getElementById("btn-stealth");
    const btnWipeout = document.getElementById("btn-wipeout");

    const sysTime = document.getElementById("sys-time");
    const sysUptime = document.getElementById("sys-uptime");
    const sysPing = document.getElementById("sys-ping");
    const sysNodes = document.getElementById("sys-nodes");

    const chatDisplay = document.getElementById("chat-display");
    const chatInput = document.getElementById("chat-input");
    const btnSend = document.getElementById("btn-send");

    const stegoImgEncode = document.getElementById("stego-image-encode");
    const stegoText = document.getElementById("stego-text");
    const btnStegoEncode = document.getElementById("btn-stego-encode");

    const stegoImgDecode = document.getElementById("stego-image-decode");
    const btnStegoDecode = document.getElementById("btn-stego-decode");
    const stegoOutput = document.getElementById("stego-output");

    const threatLog = document.getElementById("threat-log");
    const ledgerVisualizer = document.getElementById("blockchain-visualizer");
    const networkGraph = document.getElementById("network-graph");

    // ==========================================
    // 1. CLOCK, UPTIME & HEARTBEAT TELEMETRY
    // ==========================================
    setInterval(() => {
        const now = new Date();
        sysTime.textContent = now.toTimeString().split(" ")[0];

        const elapsed = Math.floor((Date.now() - bootTime) / 1000);
        const hrs = String(Math.floor(elapsed / 3600)).padStart(2, "0");
        const mins = String(Math.floor((elapsed % 3600) / 60)).padStart(2, "0");
        const secs = String(elapsed % 60).padStart(2, "0");
        sysUptime.textContent = `${hrs}:${mins}:${secs}`;
    }, 1000);

    setInterval(() => {
        if (operativeCallsign) {
            fetch("/api/comms/ping", { method: "POST" }).catch(() => {});
        }
    }, 6000);

    // ==========================================
    // 2. AUTHENTICATION & GATEWAY UPLINK
    // ==========================================
    btnLogin.addEventListener("click", async () => {
        const callsign = inputCallsign.value.trim().toUpperCase();
        const key = inputMasterKey.value.trim();

        if (!callsign || !key) {
            alert("ENTER BOTH OPERATIVE DESIGNATION AND COMSEC KEY.");
            return;
        }

        operativeCallsign = callsign;
        comsecKey = key;
        bootTime = Date.now();

        const res = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ callsign, key })
        });
        const data = await res.json();

        if (data.status === "SUCCESS") {
            gatewayZone.classList.add("hidden-zone");
            commandZone.classList.remove("hidden-zone");
            navCallsign.textContent = `OP: ${operativeCallsign} (${data.local_ip || "LOCAL"})`;
            logThreat(`UPLINK ACTIVE. ECDH + PBKDF2 ARMED.`, "status-green");
            appendChat("SYSTEM", `Welcome ${operativeCallsign}. Use @CALLSIGN <msg> for P2P ECDH, /ping for RTT, or /tamper to test RAM Watchdog.`, "status-cyan");
            renderTopology(operativeCallsign, Array.from(knownPeers), topologyDetails);
        }
    });

    // ==========================================
    // 3. ENCRYPTED TELEMETRY (XSS-SAFE CHAT)
    // ==========================================
    async function transmitMessage() {
        const message = chatInput.value.trim();
        if (!message) return;

        chatInput.value = "";
        appendChat(operativeCallsign, message, "status-green");

        const res = await fetch("/api/comms/transmit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                callsign: operativeCallsign,
                message: message,
                key: comsecKey
            })
        });
        const data = await res.json();
        if (data.system_note) {
            logThreat(data.system_note, "status-cyan");
        } else if (data.status !== "SUCCESS") {
            logThreat(`TX ERROR: ${data.message || "FAILED"}`, "status-red");
        }
    }

    btnSend.addEventListener("click", transmitMessage);
    chatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") transmitMessage();
    });

    function appendChat(sender, text, colorClass = "status-cyan") {
        const div = document.createElement("div");
        div.className = "chat-msg";
        const timeStr = new Date().toTimeString().split(" ")[0];

        const timeSpan = document.createElement("span");
        timeSpan.style.color = "var(--text-secondary)";
        timeSpan.textContent = `[${timeStr}] `;

        const senderStrong = document.createElement("strong");
        senderStrong.className = colorClass;
        senderStrong.textContent = `${sender}: `;

        const msgText = document.createTextNode(text);

        div.append(timeSpan, senderStrong, msgText);
        chatDisplay.appendChild(div);
        chatDisplay.scrollTop = chatDisplay.scrollHeight;
    }

    // ==========================================
    // 4. STEGANOGRAPHY ENCODE & DECODE
    // ==========================================
    btnStegoEncode.addEventListener("click", async () => {
        if (!stegoImgEncode.files[0] || !stegoText.value.trim()) {
            logThreat("STEGO ERROR: Select a PNG carrier image and enter secret directive.", "status-orange");
            return;
        }

        const formData = new FormData();
        formData.append("image", stegoImgEncode.files[0]);
        formData.append("message", stegoText.value.trim());
        formData.append("key", comsecKey);

        logThreat("ENCODING SPREAD-SPECTRUM PAYLOAD INTO RAM...", "status-cyan");

        const res = await fetch("/api/stego/encode", {
            method: "POST",
            body: formData
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "classified_asset.png";
            a.click();
            window.URL.revokeObjectURL(url);
            stegoText.value = "";
        } else {
            const err = await res.json();
            logThreat(`STEGO ENCODE FAILED: ${err.message}`, "status-red");
        }
    });

    btnStegoDecode.addEventListener("click", async () => {
        if (!stegoImgDecode.files[0]) {
            logThreat("STEGO ERROR: Select an encoded PNG asset to decrypt.", "status-orange");
            return;
        }

        const formData = new FormData();
        formData.append("image", stegoImgDecode.files[0]);
        formData.append("key", comsecKey);

        const res = await fetch("/api/stego/decode", {
            method: "POST",
            body: formData
        });
        const data = await res.json();

        if (res.ok && data.status === "SUCCESS") {
            stegoOutput.value = data.message;
            logThreat("COVERT ASSET SUCCESSFULLY EXTRACTED & VERIFIED.", "status-green");
        } else {
            stegoOutput.value = data.message || "DECRYPTION FAILED";
            logThreat(`STEGO DECODE ALERT: ${data.message}`, "status-red");
        }
    });

    // ==========================================
    // 5. STEALTH MODE & ZEROIZE (BURN)
    // ==========================================
    btnStealth.addEventListener("click", () => {
        document.body.classList.toggle("stealth-mode");
        const active = document.body.classList.contains("stealth-mode");
        logThreat(active ? "RED-LIGHT TACTICAL STEALTH ENGAGED" : "STANDARD HUD RESTORED", "status-orange");
    });

    btnWipeout.addEventListener("click", async () => {
        await fetch("/api/system/purge", { method: "POST" });
        chatDisplay.innerHTML = "";
        ledgerVisualizer.innerHTML = "";
        threatLog.innerHTML = "";
        logThreat("[ZEROIZED] RAM LEDGER & KEYS WIPED", "status-red");
        knownPeers.clear();
        topologyDetails = {};
        operativeCallsign = "";
        comsecKey = "";
        sysNodes.textContent = "1";
        sysPing.textContent = "-- ms";
        commandZone.classList.add("hidden-zone");
        gatewayZone.classList.remove("hidden-zone");
        inputCallsign.value = "";
        inputMasterKey.value = "";
    });

    // ==========================================
    // 6. WEBSOCKET LISTENERS (XSS-HARDENED)
    // ==========================================
    socket.on("incoming_tactical_packet", async (packet) => {
        if (!operativeCallsign || packet.sender === operativeCallsign) return;
        if (packet.destination !== "ALL" && packet.destination !== operativeCallsign) return;

        const res = await fetch("/api/comms/sync_single", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sender: packet.sender,
                payload: packet.payload,
                key: comsecKey
            })
        });

        if (res.ok) {
            const data = await res.json();
            const hopPath = packet.path ? packet.path.join(" → ") : packet.sender;
            appendChat(`${packet.sender} [${hopPath}]`, data.message, "status-cyan");
        }
    });

    socket.on("ledger_update", (block) => {
        const card = document.createElement("div");
        card.className = "ledger-card";
        const shortHash = block.hash ? block.hash.substring(0, 16) + "..." : "N/A";

        const headerRow = document.createElement("div");
        headerRow.style.display = "flex";
        headerRow.style.justifyContent = "space-between";
        headerRow.style.color = "var(--accent-cyan)";

        const agentSpan = document.createElement("span");
        agentSpan.textContent = `BLK #${block.index ?? "-"} [${block.agent || "SYS"}]`;
        const timeSpan = document.createElement("span");
        timeSpan.textContent = block.timestamp || "";
        headerRow.append(agentSpan, timeSpan);

        const actionDiv = document.createElement("div");
        actionDiv.style.margin = "4px 0";
        actionDiv.style.color = "var(--text-primary)";
        actionDiv.textContent = block.action || "";

        const hashDiv = document.createElement("div");
        hashDiv.style.color = "var(--text-secondary)";
        hashDiv.style.fontSize = "0.7rem";
        hashDiv.textContent = `SHA256: ${shortHash}`;

        card.append(headerRow, actionDiv, hashDiv);
        ledgerVisualizer.prepend(card);
    });

    socket.on("threat_alert", (alertObj) => {
        const color = alertObj.level === "CRITICAL" ? "status-red" : "status-orange";
        logThreat(`[${alertObj.level}] ${alertObj.message}`, color);
    });

    socket.on("stego_metrics", (metrics) => {
        logThreat(`STEGO QA -> PSNR: ${metrics.psnr_db} dB | MSE: ${metrics.mse} | Cap: ${metrics.capacity_percent}%`, "status-green");
    });

    socket.on("ping_update", (data) => {
        sysPing.textContent = `${data.rtt_ms} ms`;
        sysNodes.textContent = data.active_nodes;
    });

    socket.on("topology_update", (topo) => {
        knownPeers = new Set(topo.peers || []);
        topologyDetails = topo.details || {};
        sysNodes.textContent = knownPeers.size + 1;
        renderTopology(topo.local || operativeCallsign, Array.from(knownPeers), topologyDetails);
    });

    function logThreat(msg, colorClass = "status-cyan") {
        const p = document.createElement("p");
        const timeStr = new Date().toTimeString().split(" ")[0];
        p.textContent = "> ";

        const span = document.createElement("span");
        span.className = colorClass;
        span.textContent = `[${timeStr}] ${msg}`;

        p.appendChild(span);
        threatLog.prepend(p);
    }

    // ==========================================
    // 7. D3.JS MULTI-HOP MANET TOPOLOGY RADAR
    // ==========================================
    function renderTopology(centerNode, peerList, details = {}) {
        if (typeof d3 === "undefined" || !centerNode) return;
        networkGraph.innerHTML = "";

        const width = networkGraph.clientWidth || 500;
        const height = networkGraph.clientHeight || 280;

        const nodeMap = new Map();
        nodeMap.set(centerNode, { id: centerNode, group: "SELF" });

        const linkMap = new Map();
        const addEdge = (src, tgt) => {
            if (!src || !tgt || src === tgt) return;
            const key = [src, tgt].sort().join("--");
            if (!linkMap.has(key)) {
                linkMap.set(key, { source: src, target: tgt });
            }
        };

        peerList.forEach((peer) => {
            if (!peer || peer === centerNode) return;
            if (!nodeMap.has(peer)) {
                nodeMap.set(peer, { id: peer, group: "PEER" });
            }

            const peerInfo = details[peer];
            const path = (peerInfo && Array.isArray(peerInfo.path) && peerInfo.path.length > 0)
                ? peerInfo.path
                : [peer];

            // Build multi-hop chain: path[0] (origin) -> ... -> path[n-1] -> centerNode
            const fullChain = [...path, centerNode];
            for (let i = 0; i < fullChain.length - 1; i++) {
                const hopA = fullChain[i];
                const hopB = fullChain[i + 1];
                if (!nodeMap.has(hopA)) {
                    nodeMap.set(hopA, { id: hopA, group: "RELAY" });
                }
                if (!nodeMap.has(hopB)) {
                    nodeMap.set(hopB, { id: hopB, group: "RELAY" });
                }
                addEdge(hopA, hopB);
            }
        });

        const nodes = Array.from(nodeMap.values());
        const links = Array.from(linkMap.values());

        const svg = d3.select("#network-graph")
            .append("svg")
            .attr("width", width)
            .attr("height", height);

        const simulation = d3.forceSimulation(nodes)
            .force("link", d3.forceLink(links).id(d => d.id).distance(100))
            .force("charge", d3.forceManyBody().strength(-260))
            .force("center", d3.forceCenter(width / 2, height / 2));

        const link = svg.append("g")
            .selectAll("line")
            .data(links)
            .enter()
            .append("line")
            .attr("stroke", "#38bdf8")
            .attr("stroke-opacity", 0.6)
            .attr("stroke-width", 2)
            .attr("stroke-dasharray", "5,5");

        const node = svg.append("g")
            .selectAll("circle")
            .data(nodes)
            .enter()
            .append("circle")
            .attr("r", d => d.group === "SELF" ? 14 : 10)
            .attr("fill", d => d.group === "SELF" ? "#34d399" : (d.group === "RELAY" ? "#fb923c" : "#38bdf8"))
            .attr("stroke", "#06090e")
            .attr("stroke-width", 2);

        const label = svg.append("g")
            .selectAll("text")
            .data(nodes)
            .enter()
            .append("text")
            .text(d => {
                const ip = details[d.id]?.ip;
                return ip ? `${d.id} (${ip})` : d.id;
            })
            .attr("fill", "#f8fafc")
            .attr("font-family", "Share Tech Mono, monospace")
            .attr("font-size", "12px")
            .attr("dx", 16)
            .attr("dy", 4);

        simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);

            label
                .attr("x", d => d.x)
                .attr("y", d => d.y);
        });
    }
});