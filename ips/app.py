from flask import Flask, request, jsonify, render_template_string
from kubernetes import client, config
import json
import threading
import logging
import werkzeug

# Suppress Flask request logging (e.g., favicon, browser GETs)
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)

app = Flask(__name__)
lock = threading.Lock()

# Start with empty or preloaded prevention IDs
PREVENTION_IDS = set()

# Load Kubernetes in-cluster config
config.load_incluster_config()
v1 = client.CoreV1Api()

# HTML Template
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Prevention Rule Config</title>
</head>
<body>
<h2>Suricata Prevention Rule IDs</h2>
<ul id="rules"></ul>
<input type="number" id="ruleInput" placeholder="Rule ID" />
<button onclick="addRule()">Add Rule</button>

<h2>Simulate Alert</h2>
<select id="ruleSelect"></select>
<select id="namespaceSelect" onchange="fetchPods()"></select>
<select id="podSelect"></select>
<button onclick="simulateAlert()">Send Simulated Alert</button>
<pre id="simulationResult" style="background:#f4f4f4;padding:10px;"></pre>

<script>
async function fetchRules() {
  const res = await fetch('/rules');
  const data = await res.json();
  const ul = document.getElementById('rules');
  ul.innerHTML = '';
  data.forEach(rule => {
    const li = document.createElement('li');
    li.textContent = rule;
    const btn = document.createElement('button');
    btn.textContent = 'Remove';
    btn.onclick = async () => {
      await fetch('/rules/' + rule, {method: 'DELETE'});
      fetchRules(); fetchRulesForSelect();
    };
    li.appendChild(btn);
    ul.appendChild(li);
  });
}

async function addRule() {
  const input = document.getElementById('ruleInput');
  const rule = input.value;
  if (!rule) return;
  await fetch('/rules', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({"rule": parseInt(rule)})
  });
  input.value = '';
  fetchRules(); fetchRulesForSelect();
}

async function fetchRulesForSelect() {
  const res = await fetch('/rules');
  const data = await res.json();
  const select = document.getElementById('ruleSelect');
  select.innerHTML = data.map(rule => `<option value="${rule}">${rule}</option>`).join('');
}

async function fetchNamespaces() {
  const res = await fetch('/namespaces');
  const data = await res.json();
  const select = document.getElementById('namespaceSelect');
  select.innerHTML = '<option value="all">All</option>' + data.map(ns => `<option value="${ns}">${ns}</option>`).join('');
}

async function fetchPods() {
  const ns = document.getElementById('namespaceSelect').value;
  const res = await fetch('/pods/' + ns);
  const data = await res.json();
  const select = document.getElementById('podSelect');
  select.innerHTML = data.map(p => `<option value="${p.ip}">${p.name} (${p.ip})</option>`).join('');
}

async function simulateAlert() {
  const ruleId = document.getElementById('ruleSelect').value;
  const podIp = document.getElementById('podSelect').value;
  const payload = {
    alerts: [{
      annotations: {
        summary: JSON.stringify({
          alert: { signature_id: parseInt(ruleId) },
          src_ip: podIp
        })
      }
    }]
  };

  const res = await fetch('/alert', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const text = await res.text();
  document.getElementById('simulationResult').textContent = `Status: ${res.status}\\nResponse: ${text}`;
}

// Initial load
fetchRules(); fetchRulesForSelect(); fetchNamespaces();
</script>
</body>
</html>
"""

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
        if isinstance(rule, int):
            with lock:
                PREVENTION_IDS.add(rule)
            app.logger.info(f"Added rule ID {rule}")
            return jsonify({"status": "added", "rule": rule}), 201
        return jsonify({"error": "Invalid rule ID"}), 400

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
        ns_names = [ns.metadata.name for ns in namespaces.items]
        return jsonify(ns_names)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/pods/<namespace>')
def list_pods(namespace):
    try:
        if namespace == "all":
            pods = v1.list_pod_for_all_namespaces()
        else:
            pods = v1.list_namespaced_pod(namespace)
        pod_info = [{"name": pod.metadata.name, "ip": pod.status.pod_ip}
                    for pod in pods.items if pod.status.pod_ip]
        return jsonify(pod_info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/alert", methods=["POST"])
def alert():
    data = request.json
    try:
        log_line = data["alerts"][0]["annotations"]["summary"]
        event = json.loads(log_line)
        sig_id = int(event["alert"]["signature_id"])
        src_ip = event.get("src_ip")

        with lock:
            prevention_enabled = sig_id in PREVENTION_IDS

        if not prevention_enabled:
            app.logger.info(f"Detection-only alert ID {sig_id}, ignoring.")
            return "OK", 200

        # Find pod by IP and label it
        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            if pod.status.pod_ip == src_ip:
                ns = pod.metadata.namespace
                name = pod.metadata.name
                app.logger.info(f"[ALERT] Isolating pod {name} in {ns} for alert ID {sig_id}")
                v1.patch_namespaced_pod(
                    name=name,
                    namespace=ns,
                    body={"metadata": {"labels": {"security": "restricted"}}}
                )
                return "Isolated", 200

        app.logger.warning(f"No pod found with IP {src_ip}")
        return "Not found", 404
    except Exception as e:
        app.logger.error(f"Exception in /alert: {e}")
        return "Error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
