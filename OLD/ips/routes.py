from flask import request, jsonify, render_template, Response, redirect, url_for
from datetime import datetime, timezone
import ipaddress
import json
from .rules import get_rules, update_rule, delete_rule, save_rules
from .k8s_utils import (
    list_namespaces, list_pods, get_pod_details,
    label_pod, unlabel_pod, find_pod_by_ip
)

# Simples valores válidos para seguridad
VALORES_SEGURIDAD = ["solo-detectar", "detectar-registro", "confinamiento-namespace", "aislamiento-completo"]

def setup_routes(app):
    from . import log_queue, lock

    @app.route('/')
    def index():
        try:
            pods = find_pods_with_security_labels()
        except Exception as e:
            app.logger.error(f"Error loading pods with labels: {e}")
            pods = []

        return render_template("index.html", pods_con_seguridad=pods)

    def find_pods_with_security_labels():
        pods = []
        all_pods = find_pod_by_ip(None)  # obtiene todos los pods
        if not all_pods:
            return []

        for pod in all_pods:
            etiquetas = pod.metadata.labels or {}
            for key, val in etiquetas.items():
                if "seguridad" in key.lower():
                    pods.append({
                        "name": pod.metadata.name,
                        "namespace": pod.metadata.namespace,
                        "key": key,
                        "value": val
                    })
        return pods

    @app.route('/rules', methods=['GET', 'POST'])
    def manage_rules():
        if request.method == 'GET':
            with lock:
                return jsonify([
                    {"rule": rule_id, "description": r["description"], "action": r["action"]}
                    for rule_id, r in get_rules().items()
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
                update_rule(rule_id, description, action)
                save_rules(app)
            app.logger.info(f"Added rule ID {rule_id}")
            return jsonify({"status": "added", "rule": rule_id}), 201

    @app.route('/rules/<int:rule>', methods=['DELETE'])
    def remove_rule(rule):
        with lock:
            delete_rule(rule)
            save_rules(app)
        app.logger.info(f"Removed rule ID {rule}")
        return jsonify({"status": "removed", "rule": rule})

    @app.route('/namespaces')
    def get_namespaces():
        try:
            return jsonify(list_namespaces())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route('/pods/<namespace>')
    def get_pods(namespace):
        try:
            return jsonify(list_pods(namespace))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/pod-details")
    def pod_details():
        namespace = request.args.get("namespace")
        pod_name = request.args.get("pod")
        if not namespace or not pod_name:
            return jsonify({"error": "Missing parameters"}), 400
        try:
            return jsonify(get_pod_details(namespace, pod_name))
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/editar_etiqueta", methods=["POST"])
    def editar_etiqueta():
        namespace = request.form["namespace"]
        name = request.form["pod_name"]
        key = request.form["key"]
        new_value = request.form["new_value"]

        label_pod(name, namespace, key, new_value)
        return redirect(url_for("index"))

    @app.route("/unlabel", methods=["POST"])
    def quitar_etiqueta():
        namespace = request.form["namespace"]
        name = request.form["pod_name"]
        key = request.form["key"]

        unlabel_pod(name, namespace, key)
        return redirect(url_for("index"))

    @app.route("/log-stream")
    def stream_logs():
        def event_stream():
            while True:
                try:
                    msg = log_queue.get(timeout=5)
                    yield f"data: {msg}\n\n"
                except Exception:
                    continue

        return Response(event_stream(), content_type="text/event-stream")

    @app.route("/alert", methods=["POST"])
    def recibir_alerta():
        data = request.json
        app.logger.info(json.dumps(data, indent=2))

        timestamp = datetime.fromtimestamp(data["date"], timezone.utc)
        sig_id = data["signature_id"]
        src_ip = data["src_ip"]

        # Validar IP
        try:
            ip = ipaddress.ip_address(src_ip)
            if ip.version != 4:
                raise ValueError("Solo se aceptan IPv4")
        except ValueError as ve:
            app.logger.error(f"IP inválida: {src_ip} ({ve})")
            return jsonify({"error": f"Dirección IP inválida: {src_ip}", "detail": str(ve)}), 400

        app.logger.info(f"Evento recibido - Rule {sig_id}, IP {src_ip}")

        rule_info = get_rules().get(sig_id)
        if not rule_info:
            return jsonify({"mensaje": f"Regla {sig_id} no registrada"}), 200

        action = rule_info["action"]
        label_map = {
            1: "solo-detectar",
            2: "detectar-registro",
            3: "confinamiento-namespace",
            4: "aislamiento-completo"
        }

        if action not in label_map:
            return jsonify({"error": f"Acción desconocida '{action}' para regla {sig_id}"}), 400

        pod = find_pod_by_ip(src_ip)
        if pod:
            label = label_map[action]
            label_pod(pod.metadata.name, pod.metadata.namespace, "seguridad", label)
            app.logger.info(f"Etiqueta '{label}' aplicada a pod {pod.metadata.name}")
            return jsonify({
                "status": "labeled",
                "pod": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "rule_id": sig_id,
                "applied_label": {"seguridad": label},
            }), 200

        return jsonify({"error": "Pod no encontrado"}), 404

