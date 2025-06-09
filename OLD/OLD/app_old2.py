from flask import Flask, request, jsonify, render_template_string
from kubernetes import client, config
import json
import threading
import logging
import werkzeug
from datetime import datetime, timezone

# Suppress Flask default logging
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)

app = Flask(__name__)
lock = threading.Lock()
PREVENTION_IDS = set()

# Kubernetes in-cluster configuration
config.load_incluster_config()
v1 = client.CoreV1Api()

# === HTML PAGE WITH JS FIXES ===
HTML_PAGE = """
<!DOCTYPE html>
<html>
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
  <ul id="rules"></ul>
  <input type="number" id="ruleInput" placeholder="Rule ID" />
  <button onclick="addRule()">Add Rule</button>

  <hr>

  <h2>Simulate Alert</h2>

  <label>Rule ID:</label>
  <!-- Changed from select to input with datalist to allow typing and selection -->
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
    async function fetchRules() {
      const res = await fetch('/rules');
      const rules = await res.json();

      const ul = document.getElementById('rules');
      const datalist = document.getElementById('ruleOptions');
      if (!ul || !datalist) return;

      ul.innerHTML = '';
      datalist.innerHTML = '';

      rules.forEach(rule => {
        const li = document.createElement('li');
        li.textContent = rule;

        const btn = document.createElement('button');
        btn.textContent = 'Remove';
        btn.onclick = async () => {
          await fetch('/rules/' + rule, { method: 'DELETE' });
          await fetchRules();
        };

        li.appendChild(btn);
        ul.appendChild(li);

        const option = document.createElement('option');
        option.value = rule;
        datalist.appendChild(option);
      });
    }

    async function addRule() {
      const ruleValue = document.getElementById('ruleInput').value;
      const rule = parseInt(ruleValue);
      if (isNaN(rule)) {
        alert("Please enter a valid rule ID (number).");
        return;
      }

      const res = await fetch('/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule: rule })
      });

      if (res.ok) {
        document.getElementById('ruleInput').value = '';
        await fetchRules();  // Ensure refresh after addition
      } else {
        const err = await res.json();
        alert("Error: " + (err.error || 'Failed to add rule.'));
      }
    }

    async function fetchNamespaces() {
      const res = await fetch('/namespaces');
      const namespaces = await res.json();
      const nsSelect = document.getElementById('namespace');
      nsSelect.innerHTML = '<option value="">--Select--</option>';
      namespaces.forEach(ns => {
        const option = document.createElement('option');
        option.value = ns;
        option.textContent = ns;
        nsSelect.appendChild(option);
      });
    }

    async function fetchPods(namespace) {
      const res = await fetch(`/pods/${namespace}`);
      const pods = await res.json();
      const podSelect = document.getElementById('pod');
      podSelect.innerHTML = '<option value="">--Select--</option>';
      pods.forEach(p => {
        const option = document.createElement('option');
        option.value = p.name;
        option.textContent = p.name;
        option.setAttribute('data-ip', p.ip); // save IP here for later
        podSelect.appendChild(option);
      });
    }

    async function updatePodDetails() {
      const ns = document.getElementById('namespace').value;
      const pod = document.getElementById('pod').value;
      const ruleInput = document.getElementById('alertRule').value.trim();

      if (!ns || !pod || !ruleInput) {
        document.getElementById('sendAlertBtn').style.display = 'none';
        document.getElementById('curlCommand').textContent = '';
        document.getElementById('podLabels').textContent = '';
        document.getElementById('podIP').textContent = '';
        return;
      }

      const res = await fetch(`/pod-details?namespace=${ns}&pod=${pod}`);
      const data = await res.json();

      if (data.error) {
        document.getElementById('podLabels').textContent = 'Error: ' + data.error;
        document.getElementById('podIP').textContent = '';
        return;
      }

      const labelsText = Object.entries(data.labels).map(([k, v]) => `${k}: ${v}`).join('\\n') || 'No labels';
      document.getElementById('podLabels').textContent = 'Labels:\\n' + labelsText;

      // Show IP of selected pod
      document.getElementById('podIP').textContent = 'IP of selected pod is: ' + data.ip;

      // Build payload with typed or selected rule ID
      const rule = parseInt(ruleInput);
      const alertRuleId = isNaN(rule) ? ruleInput : rule;

      const payload = {
        date: Date.now() / 1000,
        log: {
          timestamp: new Date().toISOString(),
          event_type: 'alert',
          src_ip: data.ip,
          alert: {
            signature_id: parseInt(rule),
            signature: 'Alerta TEST Simulacion'
            }
          }
       };

      const curl = `curl -X POST http://localhost:5000/alert \\\n  -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(payload, null, 2)}'`;
      document.getElementById('curlCommand').textContent = curl;
      document.getElementById('sendAlertBtn').style.display = 'inline-block';
    }

    async function sendSimulatedAlert() {
      const ns = document.getElementById('namespace').value;
      const pod = document.getElementById('pod').value;
      const ruleInput = document.getElementById('alertRule').value.trim();

      if (!ns || !pod || !ruleInput) {
        appendLog("Error: Missing namespace, pod, or rule ID.");
        return;
      }

      const res = await fetch(`/pod-details?namespace=${ns}&pod=${pod}`);
      const data = await res.json();

      if (data.error) {
        appendLog("Error fetching pod details: " + data.error);
        return;
      }

      const rule = parseInt(ruleInput);
      const alertRuleId = isNaN(rule) ? ruleInput : rule;

      const payload = {
        date: Date.now() / 1000,
        log: {
          timestamp: new Date().toISOString(),
          event_type: 'alert',
          src_ip: data.ip,
          alert: {
            signature_id: parseInt(rule),
            signature: 'Alerta TEST Simulacion'
            }
          }
       };

      try {
        const postRes = await fetch('/alert', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const resultText = await postRes.text();
        appendLog("Alert sent. Server response: " + resultText);
      } catch (err) {
        appendLog("Error sending alert: " + err);
      }
    }

    function appendLog(text) {
      const logOutput = document.getElementById('logOutput');
      logOutput.textContent += text + '\\n';
      logOutput.scrollTop = logOutput.scrollHeight;
    }

    window.onload = async function () {
      await fetchRules();
      await fetchNamespaces();

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
    global PREVENTION_IDS
    if request.method == 'GET':
        with lock:
            return jsonify(sorted(PREVENTION_IDS))
    elif request.method == 'POST':
        data = request.json
        rule = data.get('rule')
        try:
            rule = int(rule)
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid rule ID"}), 400
        with lock:
            PREVENTION_IDS.add(rule)
        app.logger.info(f"Added rule ID {rule}")
        return jsonify({"status": "added", "rule": rule}), 201

@app.route('/rules/<int:rule>', methods=['DELETE'])
def delete_rule(rule):
    global PREVENTION_IDS
    with lock:
        PREVENTION_IDS.discard(rule)
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

@app.route("/alert", methods=["POST"])
def alert():
    data = request.json
    print(json.dumps(data, indent=2))
    # Parse the inner "log" string as a dictionary
    log_data = data["log"]

    # convert outer timestamp
    timestamp = datetime.fromtimestamp(data["date"], timezone.utc)
    print("Nuevo Evento recibido")
    print("-------------------- ")
    print("Event type:", log_data["event_type"])
    print("Signature:", log_data["alert"]["signature_id"])
    print("Source IP:", log_data["src_ip"])
    print("Alert message:", log_data["alert"]["signature"])
    print("Outer timestamp (UTC):", timestamp)
    print()

    try:
        event = log_data
        sig_id = int(log_data["alert"]["signature_id"])
        src_ip = log_data["src_ip"]

        with lock:
            if sig_id not in PREVENTION_IDS:
                app.logger.info(f"Alert {sig_id} is not in prevention list")
                return "Nothing to do. Rule ID "+str(sig_id)+" is not in the prevention list", 200

        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            if pod.status.pod_ip == src_ip:
                v1.patch_namespaced_pod(
                    name=pod.metadata.name,
                    namespace=pod.metadata.namespace,
                    body={"metadata": {"labels": {"security": "restricted"}}}
                )
                app.logger.info(f"Isolated pod {pod.metadata.name} in {pod.metadata.namespace}")
                return jsonify({
                    "status": "isolated",
                    "pod": pod.metadata.name,
                    "namespace": pod.metadata.namespace,
                    "rule_id": sig_id,
                    "applied_label": {"security": "restricted"},
                }), 200


        return "Pod not found", 404
    except Exception as e:
        app.logger.error(f"Exception in /alert: {e}")
        return "Error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)