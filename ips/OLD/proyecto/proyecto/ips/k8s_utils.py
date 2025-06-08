from kubernetes import client, config

config.load_incluster_config()
v1 = client.CoreV1Api()

def list_namespaces():
    return [ns.metadata.name for ns in v1.list_namespace().items]

def list_pods(namespace):
    return [{"name": pod.metadata.name, "ip": pod.status.pod_ip}
            for pod in v1.list_namespaced_pod(namespace).items if pod.status.pod_ip]

def get_pod_details(namespace, name):
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return {"ip": pod.status.pod_ip, "labels": pod.metadata.labels or {}}

def label_pod(name, namespace, key, value):
    body = {"metadata": {"labels": {key: value}}}
    return v1.patch_namespaced_pod(name=name, namespace=namespace, body=body)

def unlabel_pod(name, namespace, key):
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    labels = pod.metadata.labels or {}
    if key in labels:
        del labels[key]
    body = {"metadata": {"labels": labels}}
    return v1.patch_namespaced_pod(name=name, namespace=namespace, body=body)

def find_pod_by_ip(ip):
    pods = v1.list_pod_for_all_namespaces().items
    for pod in pods:
        if pod.status.pod_ip == ip:
            return pod
    return None

