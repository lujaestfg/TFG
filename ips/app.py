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
  <title>Alert Simulator</title>
</head>
<body>
  <h2>Configure Prevention Rule IDs</h2>
  <ul id="rules"></ul>
  <input type="number" id="ruleInput" placeholder="Rule ID" />
  <button onclick="addRule()">Add Rule</button>

  <hr>

  <h2>Simulate Alert</h2>

  <label>Rule ID:</label>
  <select id="alertRule"></select>

  <label>Namespace:</label>
  <select id="namespace"></select>

  <label>Pod:</label>
  <select id="pod"></select>

  <div id="podLabels" style="margin-top: 10px;"></div>

  <pre id="curlCommand" style="background-color: #f4f4f4; padding: 10px;"></pre>

  <button id="sendAlertBtn" onclick="sendSimulatedAlert()" style="display:none;">Send Alert Simulation</button>

  <script>
    async function fetchRules() {
      const res = await fetch('/rules');
      const rules = await res.json();
      const ul = document.getElementById('rules');
      ul.innerHTML = '';
      const select = document.getElementById('alertRule');
      select.innerHTML = '<option value="">--Select--</option>';
      rules.forEach(rule => {
        const li = document.createElement('li');
        li.textContent = rule;
        const btn = document.createElement('button');
        btn.textContent = 'Remove';
        btn.onclick = async () => {
          await fetch('/rules/' + rule, {method: 'DELETE'});
          fetchRules();
        };
        li.appendChild(btn);
        ul.appendChild(li);

        const option = document.createElement('option');
        option.value = rule;
        option.textContent = rule;
        select.appendChild(option);
      });
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
        option.value = p;
        option.textContent = p;
        podSelect.appendChild(option);
      });
    }

    async function updatePodDetails() {
      const ns = document.getElementById('namespace').value;
      const pod = document.getElementById('pod').value;
      const rule = document.getElementById('alertRule').value;

      if (!ns || !pod || !rule) {
        document.getElementById('sendAlertBtn').style.display = 'none';
        document.getElementById('curlCommand').textContent = '';
        return;
      }

      const res = await fetch(`/pod-details?namespace=${ns}&pod=${pod}`);
      const data = await res.json();

      if (data.error) {
        document.getElementById('podLabels').textContent = 'Error: ' + data.error;
        return;
      }

      const labelsText = Object.entries(data.labels).map(([k, v]) => `${k}: ${v}`).join('\n') || 'No labels';
      document.getElementById('podLabels').textContent = 'Labels:\n' + labelsText;

      const payload = {
        alerts: [{
          annotations: {
            summary: JSON.stringify({ alert: { signature_id: parseInt(rule) }, src_ip: data.ip })
          }
        }]
      };

      const curl = `curl -X POST http://localhost:5000/alert \\\n  -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(payload, null, 2)}'`;
      document.getElementById('curlCommand').textContent = curl;

      document.getElementById('sendAlertBtn').style.display = 'inline-block';
    }

    async function sendSimulatedAlert() {
      const ns = document.getElementById('namespace').value;
      const pod = document.getElementById('pod').value;
      const rule = document.getElementById('alertRule').value;

      const res = await fetch(`/pod-details?namespace=${ns}&pod=${pod}`);
      const data = await res.json();

      const payload = {
        alerts: [{
          annotations: {
            summary: JSON.stringify({ alert: { signature_id: parseInt(rule) }, src_ip: data.ip })
          }
        }]
      };

      const postRes = await fetch('/alert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const result = await postRes.text();
      alert("Response: " + result);
    }

    document.getElementById('namespace').onchange = async (e) => {
      if (e.target.value) {
        await fetchPods(e.target.value);
        document.getElementById('sendAlertBtn').style.display = 'none';
      }
    };

    document.getElementById('alertRule').onchange = updatePodDetails;
    document.getElementById('pod').onchange = updatePodDetails;

    fetchRules();
    fetchNamespaces();
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

@app.route("/pod-details")
def pod_details():
    namespace = request.args.get("namespace")
    pod_name = request.args.get("pod")
    if not namespace or not pod_name:
        return jsonify({"error": "Missing parameters"}), 400
    try:
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        return jsonify({
            "ip": pod.status.pod_ip,
            "labels": pod.metadata.labels or {}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


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
