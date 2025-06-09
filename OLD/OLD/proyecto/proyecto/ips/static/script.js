function connectLogStream() {
  const logOutput = document.getElementById("logOutput");
  const eventSource = new EventSource("/log-stream");

  eventSource.onmessage = function (event) {
    logOutput.textContent += event.data + "\n";
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

    const tdId = document.createElement('td');
    tdId.textContent = rule.rule;

    const tdDesc = document.createElement('td');
    tdDesc.textContent = rule.description;

    const tdAction = document.createElement('td');
    tdAction.textContent = actionMap[rule.action] || 'Desconocido';

    const tdButtons = document.createElement('td');

    const delBtn = document.createElement('button');
    delBtn.textContent = 'Eliminar';
    delBtn.className = 'delete-btn';
    delBtn.onclick = () => deleteRule(rule.rule);

    const editBtn = document.createElement('button');
    editBtn.textContent = 'Editar';
    editBtn.className = 'delete-btn';
    editBtn.style.backgroundColor = '#2196F3';
    editBtn.onclick = () => {
      document.getElementById('ruleInput').value = rule.rule;
      document.getElementById('ruleInput').disabled = false;
      document.getElementById('descriptionInput').value = rule.description;
      document.getElementById('actionInput').value = rule.action;
    };

    tdButtons.appendChild(delBtn);
    tdButtons.appendChild(editBtn);

    tr.appendChild(tdId);
    tr.appendChild(tdDesc);
    tr.appendChild(tdAction);
    tr.appendChild(tdButtons);
    tbody.appendChild(tr);
  });

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

  nsSelect.innerHTML = '';

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
  document.getElementById('namespace').selectedIndex = -1;
  document.getElementById('namespace').value = '';
  document.getElementById('pod').innerHTML = '';
  document.getElementById('podLabels').textContent = '';
  document.getElementById('podIP').textContent = '';
  document.getElementById('curlCommand').textContent = '';
  document.getElementById('logOutput').textContent = '';
  document.getElementById('alertRule').value = '';
  document.getElementById('sendAlertBtn').style.display = 'none';

  await fetchRules();
  await fetchNamespaces();

  connectLogStream();

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

