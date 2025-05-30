from flask import Flask, request, jsonify, render_template_string
from kubernetes import client, config
import json
import threading

app = Flask(__name__)
lock = threading.Lock()

# Start with empty or preloaded prevention IDs
PREVENTION_IDS = set()

# Load Kubernetes in-cluster config
config.load_incluster_config()
v1 = client.CoreV1Api()

# HTML for the simple UI
HTML_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Prevention Rule Config</title></head>
<body>
<h2>Suricata Prevention Rule IDs</h2>
<ul id="rules"></ul>
<input type="number" id="ruleInput" placeholder="Rule ID" />
<button onclick="addRule()">Add Rule</button>

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

fetchRules();
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
            return jsonify({"status": "added", "rule": rule}), 201
        return jsonify({"error": "Invalid rule ID"}), 400

@app.route('/rules/<int:rule>', methods=['DELETE'])
def delete_rule(rule):
    global PREVENTION_IDS
    with lock:
        PREVENTION_IDS.discard(rule)
    return jsonify({"status": "removed", "rule": rule})

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
            print(f"[INFO] Detection-only alert ID {sig_id}, ignoring.")
            return "OK", 200

        # Find pod by IP and label it (same as before)
        pods = v1.list_pod_for_all_namespaces(watch=False)
        for pod in pods.items:
            if pod.status.pod_ip == src_ip:
                ns = pod.metadata.namespace
                name = pod.metadata.name
                print(f"[ALERT] Isolating pod {name} in {ns} for alert ID {sig_id}")
                v1.patch_namespaced_pod(
                    name=name,
                    namespace=ns,
                    body={"metadata": {"labels": {"security": "restricted"}}}
                )
                return "Isolated", 200

        print(f"[WARN] No pod found with IP {src_ip}")
        return "Not found", 404
    except Exception as e:
        print(f"[ERROR] {e}")
        return "Error", 500

if __name__=="__main__":
   app.run(host="0.0.0.0", port=5000)
   
