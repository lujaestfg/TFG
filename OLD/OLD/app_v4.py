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

RULES_FILE = '/etc/rules.json'  # Ruta para persistir las reglas (montar como PVC)

def load_rules_from_file():
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
        app.logger.error(f"[load_rules_from_file] Error al parsear {RULES_FILE}: {e}")
        RULES = {}

def save_rules_to_file():
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(RULES, f)
    except Exception as e:
        app.logger.error(f"[save_rules_to_file] Error al guardar {RULES_FILE}: {e}")

# Suprimir logging por defecto de Flask
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)

app = Flask(__name__)
app.logger.info(">>> Flask logger inicializado")

lock = threading.Lock()
RULES = {}
load_rules_from_file()

log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        log_queue.put(msg)

# Configuración Kubernetes in-cluster
config.load_incluster_config()
v1 = client.CoreV1Api()

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Simulador de Alertas</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      margin: 20px;
    }
    h2 {
      color: #333;
    }
    table.rules-table, table.labeled-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 15px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
      border-radius: 8px;
      overflow: hidden;
      font-size: 14px;
    }
    table.rules-table thead, table.labeled-table thead {
      background-color: #f4f4f4;
    }
    table.rules-table th, table.rules-table td,
    table.labeled-table th, table.labeled-table td {
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    table.rules-table tbody tr:nth-child(even),
    table.labeled-table tbody tr:nth-child(even) {
      background-color: #fafafa;
    }
    table.rules-table tbody tr:hover,
    table.labeled-table tbody tr:hover {
      background-color: #f1f1f1;
    }
    button {
      padding: 6px 10px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
    }
    button.delete-btn {
      background-color: #f44336;
      color: white;
    }
    button.delete-btn:hover {
      background-color: #d32f2f;
    }
    button.edit-btn {
      background-color: #0275d8;
      color: white;
    }
    button.edit-btn:hover {
      background-color: #025aa5;
    }
    button.update-btn {
      background-color: #5cb85c;
      color: white;
    }
    button.update-btn:hover {
      background-color: #4cae4c;
    }
    button.unlabel-btn {
      background-color: #ff9800;
      color: white;
    }
    button.unlabel-btn:hover {
      background-color: #e68900;
    }
    button.modify-btn {
      background-color: #673ab7;
      color: white;
    }
    button.modify-btn:hover {
      background-color: #512da8;
    }
    input, select {
      padding: 6px;
      margin-right: 5px;
      font-size: 14px;
    }
    #logOutput {
      background-color: #eaeaea;
      height: 150px;
      overflow-y: auto;
      padding: 10px;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-family: monospace;
      white-space: pre-wrap;
    }
    #curlCommand {
      background-color: #f4f4f4;
      padding: 10px;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-family: monospace;
      white-space: pre-wrap;
      margin-top: 10px;
      margin-bottom: 10px;
    }
    label {
      margin-right: 8px;
    }
    #podLabels, #podIP {
      margin-top: 10px;
      font-family: monospace;
      white-space: pre-wrap;
    }
    hr {
      margin: 20px 0;
      border: none;
      border-top: 1px solid #ddd;
    }
  </style>
  <script>
    window.onerror = function(msg, url, lineNo, columnNo, error) {
      alert("JavaScript error: " + msg + " at " + lineNo + ":" + columnNo);
      return false;
    };

    // Conecta el stream de logs SSE
    function connectLogStream() {
      const logOutput = document.getElementById("logOutput");
      const eventSource = new EventSource("/log-stream");
      eventSource.onmessage = function(event) {
        logOutput.textContent += event.data + "\\n";
        logOutput.scrollTop = logOutput.scrollHeight;
      };
      eventSource.onerror = function(e) {
        console.error("Log stream error", e);
        eventSource.close();
      };
    }

    // ================================================
    //            REGLAS: CRUD Y EDICIÓN EN LÍNEA
    // ================================================

    async function fetchRules() {
      const res = await fetch('/rules');
      const rules = await res.json();

      const tbody = document.getElementById('rulesBody');
      tbody.innerHTML = '';

      const actionMap = {
        1: "Solo detección",
        2: "Detección con registro de ACL",
        3: "Confinamiento en namespace",
        4: "Confinamiento completo"
      };

      rules.forEach((rule) => {
        const tr = document.createElement('tr');
        tr.setAttribute('data-rule-id', rule.rule);

        tr.innerHTML = `
          <td>${rule.rule}</td>
          <td class="desc-cell">${rule.description}</td>
          <td class="action-cell">${actionMap[rule.action] || 'Desconocido'}</td>
          <td>
            <button class="edit-btn" onclick="enableEdit(${rule.rule}, '${rule.description.replace(/'/g, \"\\\\'\")}', ${rule.action})">Editar</button>
            <button class="delete-btn" onclick="deleteRule(${rule.rule})">Eliminar</button>
          </td>
        `;
        tbody.appendChild(tr);
      });

      // Actualizar datalist para simulación de alertas
      const datalist = document.getElementById('ruleOptions');
      datalist.innerHTML = '';
      rules.forEach(rule => {
        const option = document.createElement('option');
        option.value = rule.rule;
        datalist.appendChild(option);
      });
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

      // Cambiar botón Editar por botón Actualizar
      tr.querySelector('.edit-btn').outerHTML = `<button class="update-btn" onclick="updateRule(${ruleId})">Actualizar</button>`;
    }

    async function updateRule(ruleId) {
      const desc = document.getElementById(`edit-desc-${ruleId}`).value;
      const action = parseInt(document.getElementById(`edit-action-${ruleId}`).value);
      if (!desc || isNaN(action)) {
        alert("Por favor, completa correctamente los campos de edición.");
        return;
      }

      const res = await fetch(`/rules/${ruleId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: desc, action: action })
      });

      if (res.ok) {
        await fetchRules();
      } else {
        const err = await res.json();
        alert("Error al actualizar: " + (err.error || 'Desconocido'));
      }
    }

    async function deleteRule(ruleId) {
      await fetch(`/rules/${ruleId}`, { method: 'DELETE' });
      await fetchRules();
    }

    async function addRule() {
      const ruleValue = document.getElementById('ruleInput').value;
      const description = document.getElementById('descriptionInput').value;
      const action = parseInt(document.getElementById('actionInput').value);
      const rule = parseInt(ruleValue);
      if (isNaN(rule) || !description || isNaN(action)) {
        alert("Por favor, completa correctamente los campos de la nueva regla.");
        return;
      }

      const res = await fetch('/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, description, action })
      });

      if (res.ok) {
        document.getElementById('ruleInput').value = '';
        document.getElementById('descriptionInput').value = '';
        await fetchRules();
      } else {
        const err = await res.json();
        alert("Error: " + (err.error || 'No se pudo añadir la regla.'));
      }
    }

    // ====================================================
    //              SIMULACIÓN DE ALERTAS
    // ====================================================

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
        const option = document.createElement('option');
        option.value = ns;
        option.textContent = ns;
        nsSelect.appendChild(option);
      });

      document.getElementById('pod').innerHTML = '';
    }

    async function fetchPods(namespace) {
      const res = await fetch('/pods/' + namespace);
      const pods = await res.json();
      const podSelect = document.getElementById('pod');
      podSelect.innerHTML = '';
      pods.forEach(pod => {
        const option = document.createElement('option');
        option.value = pod.name;
        option.textContent = pod.name;
        podSelect.appendChild(option);
      });
      if (pods.length > 0) {
        podSelect.value = pods[0].name;
        await updatePodDetails();
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alertData)
      });

      const text = await response.text();
      document.getElementById('logOutput').textContent = text;
    }

    // ====================================================
    //           LISTA DE PODS ETIQUETADOS ("seguridad")
    // ====================================================

    async function fetchLabeledPods() {
      const res = await fetch('/labeled-pods');
      const pods = await res.json();
      const tbody = document.getElementById('labeledBody');
      tbody.innerHTML = '';

      pods.forEach(pod => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${pod.namespace}</td>
          <td>${pod.name}</td>
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
      await fetch(`/unlabel/${namespace}/${podName}`, { method: 'POST' });
      fetchLabeledPods();
      fetchRules();  // por si cambia algo en reglas
    }

    async function modifyLabel(namespace, podName) {
      const select = document.getElementById(`modify-select-${namespace}-${podName}`);
      const newLabel = select.value;
      await fetch(`/modify-label/${namespace}/${podName}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ label: newLabel })
      });
      fetchLabeledPods();
      fetchRules();
    }

    window.onload = async function () {
      await fetchRules();
      await fetchNamespaces();
      connectLogStream();
      fetchLabeledPods();

      document.getElementById('namespace').onchange = async (e) => {
        if (e.target.value) {
          await fetchPods(e.target.value);
          document.getElementById('sendAlertBtn').style.display = 'none';
          document.getElementById('podLabels').textContent = '';
          document.getElementById('podIP').textContent = '';
          document.getElementById('curlCommand').textContent = '';
          // Mantenemos Rule ID
          // document.getElementById('alertRule').value = '';
          document.getElementById('logOutput').textContent = '';
        }
      };

      document.getElementById('alertRule').oninput = updatePodDetails;
      document.getElementById('pod').onchange = updatePodDetails;
    };
  </script>
</head>
<body>
  <h2>Configurar Reglas de Prevención</h2>
  <table id="rulesTable" class="rules-table">
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

  <hr>

  <h2>Simular Alerta</h2>
  <label>Rule ID:</label>
  <input list="ruleOptions" id="alertRule" placeholder="Introduce o selecciona Rule ID" />
  <datalist id="ruleOptions"></datalist>

  <label>Namespace:</label>
  <select id="namespace"></select>

  <label>Pod:</label>
  <select id="pod"></select>

  <div id="podLabels" style="margin-top:10px; white-space: pre-wrap;"></div>
  <div id="podIP" style="margin-top:5px; font-weight:bold;"></div>
  <pre id="curlCommand" style="background-color:#f4f4f4; padding:10px;"></pre>
  <button id="sendAlertBtn" onclick="sendSimulatedAlert()" style="display:none;">Enviar Alerta Simulada</button>

  <h3>Log:</h3>
  <pre id="logOutput" style="background-color:#eaeaea; height:150px; overflow-y:auto; padding:10px;"></pre>

  <hr>

  <h2>Pods Etiquetados ("seguridad")</h2>
  <table id="labeledTable" class="labeled-table">
    <thead>
      <tr>
        <th>Namespace</th>
        <th>Pod</th>
        <th>Etiqueta</th>
        <th>Acciones</th>
      </tr>
    </thead>
    <tbody id="labeledBody"></tbody>
  </table>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

# ==========================================
# RUTAS: CRUD y EDICIÓN de reglas
# ==========================================
@app.route('/rules', methods=['GET', 'POST'])
def manage_rules():
    global RULES
    if request.method == 'GET':
        with lock:
            return jsonify([
                {"rule": rule_id, "description": r["description"], "action": r["action"]}
                for rule_id, r in RULES.items()
            ])
    # POST → crear nueva regla
    data = request.json
    try:
        rule_id = int(data.get('rule'))
        description = str(data.get('description'))
        action = int(data.get('action'))
        if action not in [1, 2, 3, 4]:
            raise ValueError("Acción inválida")
    except (ValueError, TypeError):
        return jsonify({"error": "Entrada inválida"}), 400

    with lock:
        RULES[rule_id] = {"description": description, "action": action}
        save_rules_to_file()
    app.logger.info(f"Added rule ID {rule_id}")
    return jsonify({"status": "added", "rule": rule_id}), 201

@app.route('/rules/<int:rule>', methods=['PUT'])
def update_rule(rule):
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
    global RULES
    with lock:
        RULES.pop(rule, None)
        save_rules_to_file()
    app.logger.info(f"Removed rule ID {rule}")
    return jsonify({"status": "removed", "rule": rule})

# ==========================================
# RUTAS: Kubernetes → namespaces, pods, labels
# ==========================================
@app.route('/namespaces')
def list_namespaces():
    try:
        namespaces = v1.list_namespace()
        return jsonify([ns.metadata.name for ns in namespaces.items])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pods/<namespace>')
def list_pods(namespace):
    try:
        pods = v1.list_namespaced_pod(namespace)
        return jsonify([{"name": pod.metadata.name, "ip": pod.status.pod_ip}
                        for pod in pods.items if pod.status.pod_ip])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pod-details')
def pod_details():
    namespace = request.args.get("namespace")
    pod_name = request.args.get("pod")
    if not namespace or not pod_name:
        return jsonify({"error": "Missing parameters"}), 400
    try:
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        return jsonify({"ip": pod.status.pod_ip, "labels": pod.metadata.labels or {}})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================================
# RUTAS: Alerta → aplicar etiqueta "seguridad"
# ==========================================
@app.route('/log-stream')
def stream_logs():
    def event_stream():
        while True:
            try:
                msg = log_queue.get(timeout=5)
                yield f"data: {msg}\\n\\n"
            except queue.Empty:
                continue
    return Response(event_stream(), content_type="text/event-stream")

@app.route('/alert', methods=['POST'])
def alert():
    data = request.json
    print(json.dumps(data, indent=2))

    timestamp = datetime.fromtimestamp(data.get("date", 0), timezone.utc)
    sig_id = data.get("signature_id")
    src_ip = data.get("src_ip")

    # Validación de la IP
    try:
        ip = ipaddress.ip_address(src_ip)
        if ip.version != 4:
            raise ValueError("Solo se aceptan direcciones IPv4")
    except Exception as ve:
        app.logger.error(f"Dirección IP inválida: {src_ip} ({ve})")
        return jsonify({"error": f"Dirección IP inválida: {src_ip}", "detail": str(ve)}), 400

    app.logger.info("Nuevo Evento recibido")
    app.logger.info(f"Event type: {data.get('event_type')} | Signature: {sig_id} | Source IP: {src_ip} | Timestamp: {timestamp}")

    try:
        with lock:
            rule_info = RULES.get(sig_id)

        if not rule_info:
            app.logger.info(f"Alert {sig_id} is not in rule list")
            return jsonify({"mensaje": f"Nothing to do. Rule ID {sig_id} is not in the rule list"}), 200

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

        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            if pod.status.pod_ip == src_ip:
                v1.patch_namespaced_pod(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    body={"metadata": {"labels": {"seguridad": label_value}}}
                )
                app.logger.info(f"Applied label seguridad='{label_value}' to pod {pod.metadata.name} in {pod.metadata.namespace}")
                return jsonify({
                    "status": "labeled",
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "rule_id": sig_id,
                    "applied_label": {"seguridad": label_value},
                }), 200

        return "Pod not found", 404

    except Exception as e:
        app.logger.error(f"Error handling alert: {e}")
        return jsonify({"error": str(e)}), 500

# ==========================================
# RUTAS: Obtener y modificar pods etiquetados
# ==========================================
@app.route('/labeled-pods')
def labeled_pods():
    pods_labeled = []
    try:
        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            labels = pod.metadata.labels or {}
            if 'seguridad' in labels:
                pods_labeled.append({
                    "namespace": pod.metadata.namespace,
                    "name": pod.metadata.name,
                    "label": labels.get('seguridad')
                })
        return jsonify(pods_labeled)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/unlabel/<namespace>/<pod>', methods=['POST'])
def unlabel_pod(namespace, pod):
    try:
        body = {"metadata": {"labels": {"seguridad": None}}}
        v1.patch_namespaced_pod(name=pod, namespace=namespace, body=body)
        return jsonify({"status": "unlabeled"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/modify-label/<namespace>/<pod>', methods=['POST'])
def modify_label(namespace, pod):
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

