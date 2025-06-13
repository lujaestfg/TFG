from flask import Flask, request, jsonify, render_template_string, Response
import queue
from kubernetes import client, config
import json
import threading
import logging
import werkzeug
from datetime import datetime, timezone
import os
import ipaddress

RULES_FILE = '/etc/ips/rules.json'  # Ruta para persistir las reglas (montar como PVC)

def load_rules_from_file():
    """
    Carga las reglas desde el archivo JSON persistente. Si no existe, lo crea vacío.
    Convierte las claves a int para usarlas como signature_id.
    """
    global RULES
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'w') as f:
            json.dump({}, f)
        RULES = {}
        return
    try:
        with open(RULES_FILE, 'r') as f:
            content = f.read().strip()
            if not content:
                RULES = {}
            else:
                data = json.loads(content)
                RULES = {int(k): v for k, v in data.items()}
    except Exception as e:
        # Loguea el error si el archivo no puede ser leído o parseado
        app.logger.error(f"[load_rules_from_file] Error al parsear {RULES_FILE}: {e}")
        RULES = {}

def save_rules_to_file():
    """
    Guarda las reglas actuales en el archivo JSON persistente.
    """
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(RULES, f)
    except Exception as e:
        # Loguea el error si no se puede guardar
        app.logger.error(f"[save_rules_to_file] Error al guardar {RULES_FILE}: {e}")

# Suprime el logging HTTP por defecto de Flask para limpiar la consola
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)

app = Flask(__name__)
app.logger.propagate = True
app.logger.info(">>> Flask logger inicializado")

# Cola para logs de eventos (utilizado en el stream SSE para mostrar logs en el frontend)
log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    """
    Handler personalizado para enviar logs a la cola.
    Permite mostrar eventos en tiempo real en la UI vía Server Sent Events.
    """
    def emit(self, record):
        msg = self.format(record)
        log_queue.put(msg)

# Configuración del logger raíz: solo este handler para evitar duplicados
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
for h in root_logger.handlers[:]:
    root_logger.removeHandler(h)
queue_handler = QueueHandler()
queue_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(queue_handler)

# Lock para operaciones thread-safe sobre las reglas
lock = threading.Lock()
RULES = {}
load_rules_from_file()

# Configuración para acceder a la API de Kubernetes desde dentro del clúster
config.load_incluster_config()
v1 = client.CoreV1Api()

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Panel de Control - Alertas Kubernetes</title>
  <style>
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      display: flex;
      height: 100vh;
      overflow: hidden;
    }
    #sidebar {
      width: 220px;
      background-color: #2c3e50;
      color: white;
      display: flex;
      flex-direction: column;
      padding-top: 20px;
    }
    #sidebar h2 {
      text-align: center;
      margin-bottom: 30px;
      font-size: 18px;
      letter-spacing: 1px;
    }
    #sidebar ul {
      list-style: none;
      padding: 0;
    }
    #sidebar ul li {
      padding: 15px 20px;
      cursor: pointer;
      transition: background 0.3s;
    }
    #sidebar ul li:hover, #sidebar ul li.active {
      background-color: #34495e;
    }
    #content {
      flex-grow: 1;
      padding: 20px;
      overflow-y: auto;
      background-color: #ecf0f1;
    }
    .section {
      display: none;
    }
    .section.active {
      display: block;
    }
    h2.section-title {
      color: #2c3e50;
      margin-bottom: 20px;
      font-size: 22px;
      border-bottom: 2px solid #bdc3c7;
      padding-bottom: 10px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 15px;
      background-color: white;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
      border-radius: 6px;
      overflow: hidden;
      font-size: 14px;
    }
    table thead {
      background-color: #bdc3c7;
    }
    table th, table td {
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    table tbody tr:nth-child(even) {
      background-color: #f7f7f7;
    }
    table tbody tr:hover {
      background-color: #e1e1e1;
    }
    button {
      padding: 6px 10px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
      margin-right: 5px;
      margin-top: 5px;
    }
    button.delete-btn {
      background-color: #e74c3c;
      color: white;
    }
    button.delete-btn:hover {
      background-color: #c0392b;
    }
    button.edit-btn {
      background-color: #2980b9;
      color: white;
    }
    button.edit-btn:hover {
      background-color: #1c5980;
    }
    button.update-btn {
      background-color: #27ae60;
      color: white;
    }
    button.update-btn:hover {
      background-color: #1d8f4a;
    }
    button.unlabel-btn {
      background-color: #f39c12;
      color: white;
    }
    button.unlabel-btn:hover {
      background-color: #d78b0d;
    }
    button.modify-btn {
      background-color: #8e44ad;
      color: white;
    }
    button.modify-btn:hover {
      background-color: #6f3486;
    }
    input, select {
      padding: 6px;
      margin-right: 8px;
      font-size: 14px;
      border: 1px solid #ccc;
      border-radius: 4px;
      margin-top: 5px;
    }
    #logOutput {
      background-color: #ecf0f1;
      height: 150px;
      overflow-y: auto;
      padding: 10px;
      border: 1px solid #bdc3c7;
      border-radius: 4px;
      font-family: monospace;
      white-space: pre-wrap;
      margin-top: 10px;
    }
    #curlCommand {
      background-color: #f4f4f4;
      padding: 10px;
      border: 1px solid #bdc3c7;
      border-radius: 4px;
      font-family: monospace;
      white-space: pre-wrap;
      margin-bottom: 10px;
      margin-top: 10px;
    }
    label {
      margin-right: 6px;
      font-weight: bold;
    }
    #podLabels, #podIP {
      margin-top: 10px;
      font-family: monospace;
      white-space: pre-wrap;
    }
    hr {
      margin: 20px 0;
      border: none;
      border-top: 1px solid #bdc3c7;
    }
  </style>
  <script>
function showToast(message, type="success") {
  const toast = document.getElementById('toast');
  toast.innerText = message;

  // Color según tipo
  if (type === "success") toast.style.backgroundColor = "#27ae60";
  else if (type === "error") toast.style.backgroundColor = "#e74c3c";
  else toast.style.backgroundColor = "#333";

  toast.style.visibility = "visible";
  toast.style.opacity = "1";
  toast.style.bottom = "40px";

  // Oculta después de 2 segundos
  setTimeout(function(){
    toast.style.opacity = "0";
    toast.style.bottom = "10px";
    setTimeout(function(){
      toast.style.visibility = "hidden";
    }, 500);
  }, 2000);
}
function setActiveSection(sectionId) {
  document.querySelectorAll('.section').forEach(sec => sec.classList.remove('active'));
  document.querySelectorAll('#sidebar ul li').forEach(li => li.classList.remove('active'));
  document.getElementById(sectionId).classList.add('active');
  document.getElementById('menu-' + sectionId).classList.add('active');
  if (sectionId === "logsSection") {
    connectLiveLogStream();
  }
  if (sectionId === "labeledSection") {
    fillNamespaceLabeledSelector().then(fetchLabeledPodsNamespace);
  }
}

// Llenar el selector con todos los namespaces existentes
async function fillNamespaceLabeledSelector() {
  try {
    const res = await fetch('/namespaces');
    const namespaces = await res.json();
    const nsSelect = document.getElementById('namespaceLabeled');
    nsSelect.innerHTML = ''; // Limpiar opciones

    // Opción 'All'
    const optAll = document.createElement('option');
    optAll.value = '';
    optAll.textContent = 'All';
    nsSelect.appendChild(optAll);

    namespaces.forEach(ns => {
      const opt = document.createElement('option');
      opt.value = ns;
      opt.textContent = ns;
      nsSelect.appendChild(opt);
    });

    // Selecciona "default" por defecto si existe
    if (namespaces.includes('default')) {
      nsSelect.value = 'default';
    } else {
      nsSelect.value = ''; // O "All" si no existe
    }
  } catch (err) {
    console.error('Error fetching namespaces:', err);
  }
}

// Al cargar sección/ventana:
function setupLabeledPodsSection() {
  fillNamespaceLabeledSelector().then(fetchLabeledPodsNamespace);
}

// Recarga la tabla con el filtro seleccionado

async function fetchLabeledPodsNamespace() {
  const ns = document.getElementById('namespaceLabeled').value;
  let url = '/labeled-pods';
  if (ns) url += '?namespace=' + encodeURIComponent(ns);
  const res = await fetch(url);
  const pods = await res.json();
  const tbody = document.getElementById('labeledBody');
  tbody.innerHTML = '';
  pods.forEach(pod => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${pod.namespace}</td>
      <td>${pod.name}</td>
      <td>${pod.src_ip}</td>
      <td>${pod.node}</td>
      <td>${pod.label}</td>
      <td>
        <button class="unlabel-btn" onclick="unlabelPod('${pod.namespace}', '${pod.name}')">Eliminar etiqueta</button>
        <select id="modify-select-${pod.namespace}-${pod.name}">
          <option value="solo-detectar"${pod.label==='solo-detectar'? ' selected':''}>solo-detectar</option>
          <option value="detectar-registro"${pod.label==='detectar-registro'? ' selected':''}>detectar-registro</option>
          <option value="confinamiento-namespace"${pod.label==='confinamiento-namespace'? ' selected':''}>confinamiento-namespace</option>
          <option value="aislamiento-completo"${pod.label==='aislamiento-completo'? ' selected':''}>aislamiento-completo</option>
        </select>
      <button class="modify-btn" onclick="modifyLabel('${pod.namespace}', '${pod.name}')">Modificar</button>
</td>`;
    tbody.appendChild(tr);
  });
}
    window.onload = function() {
      setActiveSection('rulesSection');
      connectLogStream();
      fetchRules();
      fetchNamespaces();
    };

    function connectLogStream() {
      const logOutput = document.getElementById("logOutput");
      if (!logOutput) return;
      const eventSource = new EventSource("/log-stream");
      eventSource.onmessage = function(event) {
        logOutput.textContent += event.data + "\\n";
        logOutput.scrollTop = logOutput.scrollHeight;
      };
      eventSource.onerror = function(e) {
        eventSource.close();
      };
    }

    // ===========================================
    //    REGLAS: CRUD + EDICIÓN EN LÍNEA
    // ===========================================
    async function fetchRules() {
      const res = await fetch('/rules');
      const rules = await res.json();

      window.ruleMap = {};
      rules.forEach(r => {
        window.ruleMap[r.rule] = {
          description: r.description,
          action: r.action
        };
      });

      const tbody = document.getElementById('rulesBody');
      tbody.innerHTML = '';
      const actionMap = {
        1: "Solo detección",
        2: "Detección con registro de ACL",
        3: "Confinamiento en namespace",
        4: "Confinamiento completo"
      };
      rules.forEach(rule => {
        const tr = document.createElement('tr');
        tr.setAttribute('data-rule-id', rule.rule);
        tr.innerHTML = `
          <td>${rule.rule}</td>
          <td class="desc-cell">${rule.description}</td>
          <td class="action-cell">${actionMap[rule.action] || 'Desconocido'}</td>
          <td>
            <button class="edit-btn" onclick="enableEdit(${rule.rule}, '${rule.description.replace(/'/g,"\\'")}', ${rule.action})">Editar</button>
            <button class="delete-btn" onclick="deleteRule(${rule.rule})">Eliminar</button>
          </td>`;
        tbody.appendChild(tr);
      });

      // Actualizar datalist
      const list = document.getElementById('ruleOptions');
      list.innerHTML = '';
      rules.forEach(rule => {
        const opt = document.createElement('option');
        opt.value = rule.rule;
        list.appendChild(opt);
      });
    }
    function updateRuleInfo() {
      const selected = parseInt(document.getElementById('alertRule').value);
      const infoSpan = document.getElementById('ruleInfo');
      if (window.ruleMap && window.ruleMap[selected]) {
        const desc = window.ruleMap[selected].description;
        const act  = window.ruleMap[selected].action;
        const actionTextMap = {
          1: "Solo detección",
          2: "Detección con registro de ACL",
          3: "Confinamiento en namespace",
          4: "Confinamiento completo"
        };
        infoSpan.textContent = `(${actionTextMap[act] || '---'}) - ${desc}`;
      } else {
        infoSpan.textContent = '';
      }
    }

    function enableEdit(ruleId, description, action) {
      const tr = document.querySelector(`tr[data-rule-id="${ruleId}"]`);
      const descCell = tr.querySelector('.desc-cell');
      const actionCell = tr.querySelector('.action-cell');
      descCell.innerHTML = `<input type="text" id="edit-desc-${ruleId}" value="${description}" />`;
      const actionOptions = {
        1: "Solo detección",
        2: "Detección con registro de ACL",
        3: "Confinamiento en namespace",
        4: "Confinamiento completo"
      };
      let selectHTML = `<select id="edit-action-${ruleId}">`;
      Object.entries(actionOptions).forEach(([val, label]) => {
        const selected = parseInt(val) === action ? "selected" : "";
        selectHTML += `<option value="${val}" ${selected}>${label}</option>`;
      });
      selectHTML += `</select>`;
      actionCell.innerHTML = selectHTML;
      tr.querySelector('.edit-btn').outerHTML = `<button class="update-btn" onclick="updateRule(${ruleId})">Actualizar</button>`;
    }

async function updateRule(ruleId) {
  const desc = document.getElementById(`edit-desc-${ruleId}`).value;
  const action = parseInt(document.getElementById(`edit-action-${ruleId}`).value);
  if (!desc || isNaN(action)) {
    showToast("Por favor, completa correctamente los campos de edición.", "error");
    return;
  }
  const res = await fetch(`/rules/${ruleId}`, {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({description: desc, action: action})
  });
  if (res.ok) {
    showToast("Regla actualizada correctamente", "success");
    fetchRules();
  } else {
    const err = await res.json();
    showToast("Error al actualizar: " + (err.error || 'Desconocido'), "error");
  }
}

async function deleteRule(ruleId) {
  const res = await fetch(`/rules/${ruleId}`, {method: 'DELETE'});
  if (res.ok) {
    showToast("Regla eliminada correctamente", "success");
    fetchRules();
  } else {
    showToast("Error eliminando la regla", "error");
  }
}

    async function addRule() {
      const ruleValue = parseInt(document.getElementById('ruleInput').value);
      const description = document.getElementById('descriptionInput').value;
      const action = parseInt(document.getElementById('actionInput').value);
      if (isNaN(ruleValue) || !description || isNaN(action)) {
        alert("Por favor, completa correctamente los campos de la nueva regla.");
        return;
      }
      await fetch('/rules', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({rule: ruleValue, description: description, action: action})
      });
      document.getElementById('ruleInput').value = '';
      document.getElementById('descriptionInput').value = '';
      fetchRules();
    }

    // =================================
    //      SIMULACIÓN DE ALERTAS
    // =================================
    async function fetchNamespaces() {
      const res = await fetch('/namespaces');
      const namespaces = await res.json();
      const nsSelect = document.getElementById('namespace');
      nsSelect.innerHTML = '';
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = '-- Selecciona Namespace --';
      placeholder.disabled = true;
      placeholder.selected = true;
      nsSelect.appendChild(placeholder);
      namespaces.forEach(ns => {
        const opt = document.createElement('option');
        opt.value = ns;
        opt.textContent = ns;
        nsSelect.appendChild(opt);
      });
      document.getElementById('pod').innerHTML = '';
    }

    async function fetchPods(namespace) {
      const res = await fetch('/pods/' + namespace);
      const pods = await res.json();
      const podSelect = document.getElementById('pod');
      podSelect.innerHTML = '';
      pods.forEach(pod => {
        const opt = document.createElement('option');
        opt.value = pod.name;
        opt.textContent = pod.name;
        podSelect.appendChild(opt);
      });
      if (pods.length > 0) {
        podSelect.value = pods[0].name;
        updatePodDetails();
      }
    }

    async function updatePodDetails() {
      const namespace = document.getElementById('namespace').value;
      const pod = document.getElementById('pod').value;
      const rule = document.getElementById('alertRule').value;
      const logOutput = document.getElementById('logOutput');
      if (namespace && pod) {
        const res = await fetch(`/pod-details?namespace=${namespace}&pod=${pod}`);
        const podData = await res.json();
        document.getElementById('podLabels').textContent =
          "Labels: " + JSON.stringify(podData.labels || {}, null, 2);
        document.getElementById('podIP').textContent =
          "Pod IP: " + (podData.ip || "N/A");
        const alertJson = {
          date: Math.floor(Date.now() / 1000),
          event_type: "alert",
          src_ip: podData.ip,
          signature_id: parseInt(rule || 0),
          signature_text: "Simulated Alert"
        };
        const curl = `curl -X POST http://<server-ip>:5000/alert -H "Content-Type: application/json" -d '${JSON.stringify(alertJson, null, 2)}'`;
        document.getElementById('curlCommand').textContent = curl;
        document.getElementById('sendAlertBtn').style.display = 'inline-block';
      } else {
        logOutput.textContent = "Por favor selecciona un namespace y un pod.";
      }
    }

    async function sendSimulatedAlert() {
      const namespace = document.getElementById('namespace').value;
      const pod = document.getElementById('pod').value;
      const rule = parseInt(document.getElementById('alertRule').value);
      const res = await fetch(`/pod-details?namespace=${namespace}&pod=${pod}`);
      const podData = await res.json();
      const alertData = {
        date: Math.floor(Date.now() / 1000),
        event_type: "alert",
        src_ip: podData.ip,
        signature_id: rule,
        signature_text: "Simulated Alert"
      };
      const response = await fetch('/alert', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(alertData)
      });
      const text = await response.text();
      document.getElementById('logOutput').textContent = text;
    }

    // ========================================
    //    LISTA Y GESTIÓN DE PODS ETIQUETADOS
    // ========================================
    async function fetchLabeledPods(ns) {
      let url = '/labeled-pods';
      if (ns) url += '?namespace=' + encodeURIComponent(ns);
      const res = await fetch(url);
      const pods = await res.json();const tbody = document.getElementById('labeledBody');
      tbody.innerHTML = '';
      pods.forEach(pod => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${pod.namespace}</td>
          <td>${pod.name}</td>
          <td>${pod.src_ip}</td>
          <td>${pod.node}</td>
          <td>${pod.label}</td>
          <td>
            <button class="unlabel-btn" onclick="unlabelPod('${pod.namespace}', '${pod.name}')">Eliminar etiqueta</button>
            <select id="modify-select-${pod.namespace}-${pod.name}">
              <option value="solo-detectar"${pod.label==='solo-detectar'? ' selected':''}>solo-detectar</option>
              <option value="detectar-registro"${pod.label==='detectar-registro'? ' selected':''}>detectar-registro</option>
              <option value="confinamiento-namespace"${pod.label==='confinamiento-namespace'? ' selected':''}>confinamiento-namespace</option>
              <option value="aislamiento-completo"${pod.label==='aislamiento-completo'? ' selected':''}>aislamiento-completo</option>
            </select>
            <button class="modify-btn" onclick="modifyLabel('${pod.namespace}', '${pod.name}')">Modificar</button>
          </td>`;
        tbody.appendChild(tr);
      });
    }

async function unlabelPod(namespace, podName) {
  const res = await fetch(`/unlabel/${namespace}/${podName}`, {method: 'POST'});
  if (res.ok) {
    showToast("Etiqueta eliminada correctamente", "success");
    fetchLabeledPodsNamespace();
  } else {
    showToast("Error eliminando la etiqueta", "error");
  }
}

// Modifica la etiqueta de seguridad del pod seleccionado
async function modifyLabel(namespace, podName) {
  // Lee el valor seleccionado en el desplegable correspondiente
  const select = document.getElementById(`modify-select-${namespace}-${podName}`);
  const newLabel = select.value;
  const res = await fetch(`/modify-label/${namespace}/${podName}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ label: newLabel })
  });
  if (res.ok) {
    showToast("Etiqueta modificada correctamente", "success");
    fetchLabeledPodsNamespace();
  } else {
    const data = await res.json();
    showToast("Error modificando la etiqueta: " + (data.error || "Desconocido"), "error");
  }
}

    function connectLiveLogStream() {
      const logOutput = document.getElementById("liveLogOutput");
      if (!logOutput) return;
      logOutput.textContent = ""; // Limpiar al cambiar de sección
      const eventSource = new EventSource("/log-stream");
      eventSource.onmessage = function(event) {
        logOutput.textContent += event.data + "\\n";
        logOutput.scrollTop = logOutput.scrollHeight;
      };
      eventSource.onerror = function(e) {
        logOutput.textContent += "[stream disconnected]\\n";
        eventSource.close();
      };
    }
  </script>
</head>
<body>
  <div id="sidebar">
    <h2>IPS LUJAES</h2>
    <ul>
      <li id="menu-rulesSection" onclick="setActiveSection('rulesSection')">Configurar Reglas</li>
      <li id="menu-simulateSection" onclick="setActiveSection('simulateSection')">Simular Alerta</li>
      <li id="menu-labeledSection" onclick="setActiveSection('labeledSection')">Pods Etiquetados</li>
      <li id="menu-grafanaSection" onclick="setActiveSection('grafanaSection')">Grafana</li>
      <li id="menu-logsSection" onclick="setActiveSection('logsSection')">Eventos en Vivo</li>
    </ul>
  </div>
  <div id="content">
    <div id="rulesSection" class="section">
      <h2 class="section-title">Configurar Reglas de Prevención</h2>
      <table id="rulesTable">
        <thead>
          <tr>
            <th>ID</th>
            <th>Descripción</th>
            <th>Acción</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody id="rulesBody"></tbody>
      </table>
      <input type="number" id="ruleInput" placeholder="Rule ID" />
      <input type="text" id="descriptionInput" placeholder="Descripción" />
      <select id="actionInput">
        <option value="1">Solo detección</option>
        <option value="2">Detección con registro de ACL</option>
        <option value="3">Confinamiento en namespace</option>
        <option value="4">Confinamiento completo</option>
      </select>
      <button onclick="addRule()">Añadir Regla</button>
    </div>
    <div id="simulateSection" class="section">
      <h2 class="section-title">Simular Alerta</h2>
      <label>Rule ID:</label>
      <input list="ruleOptions" id="alertRule" placeholder="Introduce o selecciona Rule ID" oninput="updateRuleInfo()">
      <datalist id="ruleOptions"></datalist>
      <span id="ruleInfo" style="margin-left: 20px; font-weight: bold;"></span>
      <br><br>
      <label>Namespace:</label>
      <select id="namespace" onchange="fetchPods(this.value)"></select>
      <label>Pod:</label>
      <select id="pod" onchange="updatePodDetails()"></select><br>
      <div id="podLabels"></div>
      <div id="podIP"></div>
      <pre id="curlCommand"></pre>
      <button id="sendAlertBtn" onclick="sendSimulatedAlert()" style="display:none;">Enviar Alerta Simulada</button>
      <h3 style="margin-top:20px;">Log:</h3>
      <pre id="logOutput"></pre>
    </div>
    <div id="labeledSection" class="section">
  <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
    <h2 class="section-title">Pods Etiquetados para Seguridad</h2>
    <div>
      <label for="namespaceLabeled">Namespace:</label>
      <select id="namespaceLabeled" onchange="fetchLabeledPodsNamespace()">
        <option value="">All</option>
      </select>
      <button class="modify-btn" onclick="fetchLabeledPodsNamespace()">Refresh</button>
    </div>
  </div>
  <table id="labeledTable">
    <thead>
      <tr>
        <th>Namespace</th>
        <th>Pod</th>
        <th>Src IP</th>
        <th>Node</th>
        <th>Etiqueta</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody id="labeledBody"></tbody>
  </table>
</div>
<div id="grafanaSection" class="section" style="padding:0;margin:0;">
      <iframe src="http://192.168.1.222/d/9efe89e9-11e7-4267-8bc1-7731da6b9a05/suricata-dashboard?orgId=1&from=now-1h&to=now&timezone=browser&var-namespace=default&var-pod=$__all&refresh=auto&theme=light&kiosk=tv"
        id="grafanaFrame"
        style="width:100%;height:calc(100vh - 0px);border:none;display:block;"
        frameborder="0"
        allowfullscreen
      ></iframe>
    </div>
    <div id="logsSection" class="section" style="padding:0;margin:0;">
      <h2 class="section-title">Eventos en Vivo</h2>
      <pre id="liveLogOutput" style="height: 80vh; overflow-y: auto; background: #1a1a1a; color: #fff; padding: 15px; border-radius: 8px; font-size: 13px;"></pre>
    </div>
  </div>
  <div id="toast" style="
  visibility: hidden;
  min-width: 200px;
  margin-left: -100px;
  background-color: #333;
  color: #fff;
  text-align: center;
  border-radius: 8px;
  padding: 14px;
  position: fixed;
  z-index: 10000;
  left: 50%;
  bottom: 40px;
  font-size: 16px;
  opacity: 0;
  transition: opacity 0.5s, bottom 0.5s;
"></div>

</body>
</html>
"""

@app.route('/')
def index():
    """
    Devuelve el frontend principal embebido (panel de control).
    """
    return render_template_string(HTML_PAGE)


# --- Gestión de Reglas de Prevención (CRUD) ---

@app.route('/rules', methods=['GET', 'POST'])
def manage_rules():
    """
    GET: Devuelve la lista de reglas (signature_id, descripción, acción).
    POST: Añade una nueva regla o la sobrescribe si ya existe.
    """
    global RULES
    if request.method == 'GET':
        with lock:
            return jsonify([
                {"rule": rule_id, "description": r["description"], "action": r["action"]}
                for rule_id, r in RULES.items()
            ])
    data = request.json
    try:
        rule_id = int(data.get('rule'))
        description = str(data.get('description'))
        action = int(data.get('action'))
        if action not in [1, 2, 3, 4]:
            raise ValueError("Acción inválida")
        if not description.strip():
            return jsonify({"error": "La descripción no puede estar vacía"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Entrada inválida"}), 400
    with lock:
        RULES[rule_id] = {"description": description, "action": action}
        save_rules_to_file()
    app.logger.info(f"Added rule ID {rule_id}")
    return jsonify({"status": "added", "rule": rule_id}), 201

@app.route('/rules/<int:rule>', methods=['PUT'])
def update_rule(rule):
    """
    Actualiza una regla existente por ID.
    """
    global RULES
    data = request.json
    try:
        description = str(data.get('description'))
        action = int(data.get('action'))
        if action not in [1, 2, 3, 4]:
            raise ValueError("Acción inválida")
    except Exception:
        return jsonify({"error": "Entrada inválida"}), 400
    with lock:
        if rule not in RULES:
            return jsonify({"error": f"Regla {rule} no encontrada"}), 404
        RULES[rule] = {"description": description, "action": action}
        save_rules_to_file()
    app.logger.info(f"Updated rule ID {rule}")
    return jsonify({"status": "updated", "rule": rule}), 200

@app.route('/rules/<int:rule>', methods=['DELETE'])
def delete_rule(rule):
    """
    Elimina una regla por ID.
    """
    global RULES
    with lock:
        RULES.pop(rule, None)
        save_rules_to_file()
    app.logger.info(f"Removed rule ID {rule}")
    return jsonify({"status": "removed", "rule": rule})

# --- Namespaces y Pods ---

@app.route('/namespaces')
def list_namespaces():
    """
    Devuelve la lista de namespaces presentes en el cluster.
    """
    try:
        namespaces = v1.list_namespace()
        return jsonify([ns.metadata.name for ns in namespaces.items])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pods/<namespace>')
def list_pods(namespace):
    """
    Devuelve la lista de pods en un namespace específico (con su IP).
    """
    try:
        pods = v1.list_namespaced_pod(namespace)
        return jsonify([{"name": pod.metadata.name, "ip": pod.status.pod_ip} for pod in pods.items if pod.status.pod_ip])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pod-details')
def pod_details():
    """
    Devuelve información de un pod concreto (IP y etiquetas).
    """
    namespace = request.args.get("namespace")
    pod_name = request.args.get("pod")
    if not namespace or not pod_name:
        return jsonify({"error": "Missing parameters"}), 400
    try:
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        return jsonify({"ip": pod.status.pod_ip, "labels": pod.metadata.labels or {}})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Log streaming en vivo (Server Sent Events para el frontend) ---

@app.route('/log-stream')
def stream_logs():
    """
    Devuelve un stream SSE con los logs de eventos en tiempo real para el frontend.
    """
    def event_stream():
        while True:
            try:
                msg = log_queue.get(timeout=5)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                continue
    return Response(event_stream(), content_type="text/event-stream")

# --- Recepción de alertas (acción automática sobre pods) ---

@app.route('/alert', methods=['POST'])
def alert():
    """
    Recibe una alerta en formato JSON, identifica el pod por IP y aplica la acción configurada:
    - Etiqueta el pod según la acción de la regla.
    - Si no hay regla asociada, no realiza acción.
    """
    data = request.json
    timestamp = datetime.fromtimestamp(data.get("date", 0), timezone.utc)
    sig_id = data.get("signature_id")
    src_ip = data.get("src_ip")
    # Valida que la IP es IPv4 válida
    try:
        ip = ipaddress.ip_address(src_ip)
        if ip.version != 4:
            raise ValueError("Solo se aceptan direcciones IPv4")
    except Exception as ve:
        app.logger.error(f"Dirección IP inválida: {src_ip} ({ve})")
        return jsonify({"error": f"Dirección IP inválida: {src_ip}", "detail": str(ve)}), 400
    app.logger.info("Nuevo Evento recibido")
    app.logger.info(json.dumps(data, ensure_ascii=False))
    app.logger.info(f"Event type: {data.get('event_type')} | Signature: {sig_id} | Source IP: {src_ip} | Timestamp: {timestamp}")
    try:
        with lock:
            rule_info = RULES.get(sig_id)
        if not rule_info:
            app.logger.info(f"Firma {sig_id} no esta en la lista de reglas de IPS")
            return jsonify({"mensaje": f"Nada que hacer. Rule ID {sig_id} no esta en la lista de reglas IPS"}), 200
        action = rule_info.get("action")
        label_map = {
            1: "solo-detectar",
            2: "detectar-registro",
            3: "confinamiento-namespace",
            4: "aislamiento-completo"
        }
        if action not in label_map:
            return jsonify({"error": f"Acción desconocida '{action}' para la regla {sig_id}"}), 400
        label_value = label_map[action]
        # Busca el pod con la IP indicada y lo etiqueta
        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            if pod.status.pod_ip == src_ip:
                v1.patch_namespaced_pod(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    body={"metadata": {"labels": {"seguridad": label_value}}}
                )
                app.logger.info(f"POD etiquetado. Label --> seguridad='{label_value}' al pod {pod.metadata.name} en el namespace {pod.metadata.namespace}")
                return jsonify({
                    "status": "labeled",
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "rule_id": sig_id,
                    "applied_label": {"seguridad": label_value},
                }), 200
        return jsonify({"error": "Pod no encontrado"}), 404
    except Exception as e:
        app.logger.error(f"Error handling alert: {e}")
        return jsonify({"error": str(e)}), 500

# --- Listado y gestión de pods etiquetados para seguridad ---

@app.route('/labeled-pods')
def labeled_pods():
    """
    Devuelve todos los pods etiquetados con alguna acción de seguridad.
    Permite filtrar por namespace mediante parámetro GET (?namespace=...).
    """
    ns = request.args.get("namespace")
    pods_labeled = []
    try:
        if ns:
            pods = v1.list_namespaced_pod(ns)
        else:
            pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            labels = pod.metadata.labels or {}
            if 'seguridad' in labels and labels['seguridad']:
                pods_labeled.append({
                    "namespace": pod.metadata.namespace,
                    "name": pod.metadata.name,
                    "src_ip": pod.status.pod_ip,
                    "node": pod.spec.node_name,
                    "label": labels.get('seguridad')
                })
        return jsonify(pods_labeled)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/unlabel/<namespace>/<pod>', methods=['POST'])
def unlabel_pod(namespace, pod):
    """
    Elimina la etiqueta 'seguridad' de un pod concreto.
    """
    try:
        patch = {
            "metadata": {
                "labels": {
                    "seguridad": None
                }
            }
        }
        v1.patch_namespaced_pod(
            name=pod,
            namespace=namespace,
            body=patch
        )
        app.logger.info(f"Patch enviado para eliminar 'seguridad' de {pod} en {namespace}")
        return jsonify({"status": "unlabeled"}), 200
    except Exception as e:
        app.logger.error(f"Error eliminando etiqueta: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/modify-label/<namespace>/<pod>', methods=['POST'])
def modify_label(namespace, pod):
    """
    Modifica el valor de la etiqueta 'seguridad' para un pod concreto.
    """
    data = request.json
    new_label = data.get("label")
    if new_label not in ["solo-detectar", "detectar-registro", "confinamiento-namespace", "aislamiento-completo"]:
        return jsonify({"error": "Etiqueta inválida"}), 400
    try:
        body = {"metadata": {"labels": {"seguridad": new_label}}}
        v1.patch_namespaced_pod(name=pod, namespace=namespace, body=body)
        return jsonify({"status": "modified"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- Ruta extra para debug visual del estado de pods y etiquetas ---
@app.route('/debug-pods')
def debug_pods():
    """
    Devuelve todos los pods y sus etiquetas, útil para depuración rápida.
    """
    pods = v1.list_pod_for_all_namespaces(watch=False)
    output = []
    for pod in pods.items:
        output.append(f"{pod.metadata.namespace}/{pod.metadata.name} {pod.metadata.labels}")
    return "<br>".join(output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)