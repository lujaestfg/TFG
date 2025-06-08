import json
import os

RULES_FILE = '/etc/ips/rules.json'
RULES = {}

def load_rules(app):
    global RULES
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'w') as f:
            json.dump({}, f)
        RULES = {}
        return

    try:
        with open(RULES_FILE, 'r') as f:
            content = f.read().strip()
            RULES = json.loads(content) if content else {}
            RULES = {int(k): v for k, v in RULES.items()}
    except Exception as e:
        app.logger.error(f"Error loading rules: {e}")
        RULES = {}

def save_rules(app):
    try:
        with open(RULES_FILE, 'w') as f:
            json.dump(RULES, f)
    except Exception as e:
        app.logger.error(f"Error saving rules: {e}")

def get_rules():
    return RULES

def update_rule(rule_id, description, action):
    RULES[rule_id] = {"description": description, "action": action}

def delete_rule(rule_id):
    RULES.pop(rule_id, None)

