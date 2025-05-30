from flask import Flask, request, jsonify, render_template_string
from kubernetes import client, config
import json
import threading
import logging
from io import StringIO
import logging
import werkzeug

werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.ERROR)  # or logging.CRITICAL to silence all

app = Flask(__name__)
lock = threading.Lock()

# Setup in-cluster or fallback kube config
try:
    config.load_incluster_config()
except config.ConfigException:
    config.load_kube_config()

v1 = client.CoreV1Api()

# Prevention rule ID storage
PREVENTION_IDS = set()

# In-memory log storage
log_stream = StringIO()
logging.basicConfig(stream=log_stream, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)

# HTML with embedded JavaScript for dynamic UI
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head><title>K8s Pod Isolation Webhook</title></head>
<body>
<h2>Suricata Prevention Rule IDs</h2>
<ul id="rules"></ul>
<input type="number" id="ruleInput" placeholder="Rule ID" />
<button onclick="addRule()">Add Rule</button>

<h2>Simulate Alert</h2>
<select id="methodSelect">
  <option value="POST">POST</option>
  <option value="GET">GET</option>
</select>
<br/>
<textarea id="payloadInput" rows="8" cols="50" placeholder="Paste JSON here for POST..."></textarea><br/>
<button onclick="simulateAlert()">Send</button>
<pre id="alertResponse"></pre>

<h2>Webhook Log</h2>
<pre id="logBox" style="background:#eee; padding:10px; height:200px; overflow-y:scroll;"></pre>

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
      fetchRules();
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
  fetchRules();
}

async function simulateAlert() {
  const method = document.getElementById("methodSelect").value;
  const payload = document.getElementById("payloadInput").value;
  let res;
  try {
    if (method === "POST") {
      res = await fetch("/alert", {
        method: "POST",
        headers: {'Content-Type': 'application/json'},
        body: payload
      });
    } else {
      res = await fetch("/alert");
    }
    const text = await res.text();
    document.getElementById("alertResponse").textContent = "Status: " + res.status + "\\n" + text;
  } catch (e) {
    document.getElementById("alertResponse").textContent = "Error: " + e;
  }
}

async function pollLog() {
  const res = await fetch("/logs");
  const text = await res.text();
  const logBox = document.getElementById("logBox");
  logBox.textContent = text;
  logBox.scrollTop = logBox.scrollHeight;
}

fetchRules();
setInterval(pollLog, 2000);
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
            log.info(f"Added rule ID {rule}")
            return jsonify({"status": "added", "rule": rule}), 201
        return jsonify({"error": "Invalid rule ID"}), 400

@app.route('/rules/<int:rule>', methods=['DELETE'])
def delete_rule(rule):
    global PREVENTION_IDS
    with lock:
        PREVENTION_IDS.discard(rule)
    log.info(f"Removed rule ID {rule}")
    return jsonify({"status": "removed", "rule": rule})

@app.route('/logs')
def logs():
    return log_stream.getvalue(), 200, {'Content-Type': 'text/plain'}

@app.route("/alert", methods=["POST", "GET"])
def alert():
    if request.method == "GET":
        # For testing, simulate a fake alert
        return jsonify({"message": "GET received"}), 200

    try:
        data = request.json
        log_line = data["alerts"][0]["annotations"]["summary"]
        event = json.loads(log_line)
        sig_id = int(event["alert"]["signature_id"])
        src_ip = event.get("src_ip")

        with lock:
            prevention_enabled = sig_id in PREVENTION_IDS

        if not prevention_enabled:
            log.info(f"Detection-only alert ID {sig_id}, ignoring.")
            return "OK", 200

        # Find pod by IP
        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            if pod.status.pod_ip == src_ip:
                ns = pod.metadata.namespace
                name = pod.metadata.name
                labels = pod.metadata.labels or {}
                if labels.get("security") != "restricted":
                    labels["security"] = "restricted"
                    v1.patch_namespaced_pod(
                        name=name,
                        namespace=ns,
                        body={"metadata": {"labels": labels}}
                    )
                    log.info(f"[ALERT] Isolated pod {name} in {ns} due to alert ID {sig_id}")
                    return "Isolated", 200
                else:
                    log.info(f"[ALERT] Pod {name} already restricted")
                    return "Already restricted", 200

        log.warning(f"No pod found with IP {src_ip}")
        return "Not found", 404

    except Exception as e:
        log.error(f"Exception in /alert: {e}")
        return "Error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
