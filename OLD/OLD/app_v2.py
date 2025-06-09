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

RULES_FILE = '/etc/rules.json' # esta ruta tendría que ser un PVC para persistencia

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
                # Convertir claves a enteros si son numéricas
                RULES = {int(k): v for k, v in data.items()}
    except Exception as e:
        app.logger.error(f"[load_rules_from_file] Error parsing {RULES_FILE}: {e}")
        RULES = {}

def save_rules_to_file():
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(RULES, f)
    except Exception as e:
        app.logger.error(f"Error saving rules to file: {e}")


# Suppress Flask default logging
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.INFO)

app = Flask(__name__)

print(">>> Flask app is starting...")
app.logger.info(">>> Flask logger initialized")

lock = threading.Lock()

RULES = {}  # rule_id: {"description": str, "action": int}

load_rules_from_file() # lee el fichero de reglas

log_queue = queue.Queue()

class QueueHandler(logging.Handler):
    def emit(self, record):
        msg = self.format(record)
        log_queue.put(msg)



# Kubernetes in-cluster configuration
config.load_incluster_config()
v1 = client.CoreV1Api()

# === HTML PAGE WITH JS FIXES ===
HTML_PAGE = """
<!DOCTYPE html>
<html>
<style>
  table.rules-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 15px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    border-radius: 8px;
    overflow: hidden;
    font-family: sans-serif;
    font-size: 14px;
  }

  table.rules-table thead {
    background-color: #f4f4f4;
  }

  table.rules-table th, table.rules-table td {
    padding: 12px 10px;
    text-align: left;
    border-bottom: 1px solid #ddd;
  }

  table.rules-table tbody tr:nth-child(even) {
    background-color: #fafafa;
  }

  table.rules-table tbody tr:hover {
    background-color: #f1f1f1;
  }

  button.delete-btn {
    background-color: #f44336;
    color: white;
    border: none;
    padding: 6px 10px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 13px;
  }

  button.delete-btn:hover {
    background-color: #d32f2f;
  }
</style>

<head>
  <title>Alert Simulator</title>
  <script>
    window.onerror = function(msg, url, lineNo, columnNo, error) {
      alert("JavaScript error: " + msg + " at " + lineNo + ":" + columnNo);
      return false;
    };
  </script>
</head>
<body>
  <h2>Configure Prevention Rule IDs</h2>
  <table id="rulesTable" class="rules-table">
  <thead>
    <tr style="background-color: #f0f0f0;">
      <th style="padding: 8px; border: 1px solid #ccc;">ID</th>
      <th style="padding: 8px; border: 1px solid #ccc;">Descripción</th>
      <th style="padding: 8px; border: 1px solid #ccc;">Acción</th>
      <th style="padding: 8px; border: 1px solid #ccc;">Acciones</th>
    </tr>
  </thead>
  <tbody id="rulesBody"></tbody>
</table>
<input type="number" id="ruleInput" placeholder="Rule ID" />
  <input type="text" id="descriptionInput" placeholder="Description" />
  <select id="actionInput">
    <option value="1">Solo detección</option>
    <option value="2">Detección con registro de ACL</option>
    <option value="3">Confinamiento en namespace</option>
    <option value="4">Confinamiento completo</option>
  </select>
  <button onclick="addRule()">Add Rule</button>

  <hr>

  <h2>Simulate Alert</h2>

  <label>Rule ID:</label>
  <input list="ruleOptions" id="alertRule" placeholder="Enter or select rule ID" />
  <datalist id="ruleOptions"></datalist>

  <label>Namespace:</label>
  <select id="namespace"></select>

  <label>Pod:</label>
  <select id="pod"></select>

  <div id="podLabels" style="margin-top: 10px; white-space: pre-wrap;"></div>
  <div id="podIP" style="margin-top: 5px; font-weight: bold;"></div>

  <pre id="curlCommand" style="background-color: #f4f4f4; padding: 10px;"></pre>

  <button id="sendAlertBtn" onclick="sendSimulatedAlert()" style="display:none;">Send Alert Simulation</button>

  <h3>Log:</h3>
  <pre id="logOutput" style="background-color: #eaeaea; height: 150px; overflow-y: auto; padding: 10px;"></pre>

<script>
  function connectLogStream() {
     const logOutput = document.getElementById("logOutput");
     const eventSource = new EventSource("/log-stream");

     eventSource.onmessage = function (event) {
       logOutput.textContent += event.data + "\\n";
       logOutput.scrollTop = logOutput.scrollHeight;
     };

     eventSource.onerror = function (e) {
       console.error("Log stream error", e);
       eventSource.close();
    };
  }
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

  rules.forEach((rule, index) => {
    const tr = document.createElement('tr');
    tr.style.backgroundColor = index % 2 === 0 ? '#ffffff' : '#f9f9f9';

    tr.innerHTML = `
      <td style="padding: 8px; border: 1px solid #ccc;">${rule.rule}</td>
      <td style="padding: 8px; border: 1px solid #ccc;">${rule.description}</td>
      <td style="padding: 8px; border: 1px solid #ccc;">${actionMap[rule.action] || 'Desconocido'}</td>
    <td>
     <button class="delete-btn" onclick="deleteRule(${rule.rule})">Eliminar</button>
    </td>
  `;

    tbody.appendChild(tr);
  });

  // También actualizar datalist para selector de alertas
  const datalist = document.getElementById('ruleOptions');
  datalist.innerHTML = '';
  rules.forEach(rule => {
    const option = document.createElement('option');
    option.value = rule.rule;
    datalist.appendChild(option);
  });
}

async function deleteRule(ruleId) {
  await fetch('/rules/' + ruleId, { method: 'DELETE' });
  await fetchRules();
}

  async function addRule() {
    const ruleValue = document.getElementById('ruleInput').value;
    const description = document.getElementById('descriptionInput').value;
    const action = parseInt(document.getElementById('actionInput').value);
    const rule = parseInt(ruleValue);
    if (isNaN(rule) || !description || isNaN(action)) {
      alert("Please fill all rule fields correctly.");
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
      alert("Error: " + (err.error || 'Failed to add rule.'));
    }
  }

  async function fetchNamespaces() {
      const res = await fetch('/namespaces');
      const namespaces = await res.json();
      const nsSelect = document.getElementById('namespace');

      // Limpiar contenido del selector
      nsSelect.innerHTML = '';

      // Agregar un option vacío (desactivado por defecto)
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = '-- Select Namespace --';
      placeholder.disabled = true;
      placeholder.selected = true;
      nsSelect.appendChild(placeholder);

      namespaces.forEach(ns => {
        const option = document.createElement('option');
        option.value = ns;
        option.textContent = ns;
        nsSelect.appendChild(option);
      });

      // No seleccionar nada automáticamente
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
      logOutput.textContent = "Please select a namespace and a pod.";
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

window.onload = async function () {
  // Reiniciar valores de todos los campos manualmente
  document.getElementById('namespace').selectedIndex = -1;
  document.getElementById('namespace').value = '';
  document.getElementById('pod').innerHTML = '';
  document.getElementById('podLabels').textContent = '';
  document.getElementById('podIP').textContent = '';
  document.getElementById('curlCommand').textContent = '';
  document.getElementById('logOutput').textContent = '';
  document.getElementById('alertRule').value = '';
  document.getElementById('sendAlertBtn').style.display = 'none';

  // Luego cargar la info real
  await fetchRules();
  await fetchNamespaces();

  connectLogStream(); // Conecta el stream de logs

  document.getElementById('namespace').onchange = async (e) => {
    if (e.target.value) {
      await fetchPods(e.target.value);
      document.getElementById('sendAlertBtn').style.display = 'none';
      document.getElementById('podLabels').textContent = '';
      document.getElementById('podIP').textContent = '';
      document.getElementById('curlCommand').textContent = '';
      document.getElementById('alertRule').value = '';
      document.getElementById('logOutput').textContent = '';
    }
  };

  document.getElementById('alertRule').oninput = updatePodDetails;
  document.getElementById('pod').onchange = updatePodDetails;
};


</script>
</body>
</html>
"""

# === ROUTES ===

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/rules', methods=['GET', 'POST'])
def manage_rules():
    global RULES
    if request.method == 'GET':
        with lock:
            return jsonify([
                {"rule": rule_id, "description": r["description"], "action": r["action"]}
                for rule_id, r in RULES.items()
            ])
    elif request.method == 'POST':
        data = request.json
        try:
            rule_id = int(data.get('rule'))
            description = str(data.get('description'))
            action = int(data.get('action'))
            if action not in [1, 2, 3, 4]:
                raise ValueError("Invalid action")
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid input"}), 400

        with lock:
            RULES[rule_id] = {"description": description, "action": action}
            save_rules_to_file()  # Guardamos a disco
        app.logger.info(f"Added rule ID {rule_id}")
        return jsonify({"status": "added", "rule": rule_id}), 201

@app.route('/rules/<int:rule>', methods=['DELETE'])
def delete_rule(rule):
    global RULES
    with lock:
        RULES.pop(rule, None)
        save_rules_to_file()
    app.logger.info(f"Removed rule ID {rule}")
    return jsonify({"status": "removed", "rule": rule})

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

@app.route("/pod-details")
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

@app.route("/log-stream")
def stream_logs():
    def event_stream():
        while True:
            try:
                msg = log_queue.get(timeout=5)
                yield f"data: {msg}\n\n"
            except queue.Empty:
                continue

    return Response(event_stream(), content_type="text/event-stream")

@app.route("/alert", methods=["POST"])
def alert():
    data = request.json
    print(json.dumps(data, indent=2))

    timestamp = datetime.fromtimestamp(data["date"], timezone.utc)
    sig_id = data["signature_id"]
    src_ip = data["src_ip"]

    # Validación de la IP
    try:
       ip = ipaddress.ip_address(src_ip)
       if ip.version != 4:
          raise ValueError("Solo se aceptan direcciones IPv4")
    except ValueError as ve:
       app.logger.error(f"Dirección IP inválida: {src_ip} ({ve})")
       return jsonify({
          "error": f"Dirección IP inválida: {src_ip}",
          "detail": str(ve)
       }), 400

    print("Nuevo Evento recibido")
    print("-------------------- ")
    print("Event type:", data["event_type"])
    print("Signature:", sig_id)
    print("Source IP:", src_ip)
    print("Alert message:", data["signature_text"])
    print("Outer timestamp (UTC):", timestamp)
    print()

    app.logger.info("Nuevo Evento recibido")
    app.logger.info("-------------------- ")
    app.logger.info(f"Event type: {data['event_type']}")
    app.logger.info(f"Signature: {sig_id}")
    app.logger.info(f"Source IP: {src_ip}")
    app.logger.info(f"Alert message: {data['signature_text']}")
    app.logger.info(f"Outer timestamp (UTC): {timestamp}")


    try:
        with lock:
            rule_info = RULES.get(sig_id)

        if not rule_info:
            app.logger.info(f"Alert {sig_id} is not in rule list")
            return jsonify({
                "mensaje": f"Nothing to do. Rule ID {sig_id} is not in the rule list"
              }), 200

        action = rule_info["action"]
        label_map = {
            1: "solo-detectar",
            2: "detectar-registro",
            3: "confinamiento-namespace",
            4: "aislamiento-completo"
        }
        if action not in label_map:
         return jsonify({
            "error": f"Acción desconocida '{action}' para la regla {sig_id}"
           }), 400
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
                print(f"Applied label seguridad='{label_value} to pod {pod.metadata.name} in {pod.metadata.namespace}")
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
