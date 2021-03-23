import os
import json

TARGET_PATH = os.environ['HOME'] + "/targets/chaos-bugbounty-list.json" # https://github.com/projectdiscovery/public-bugbounty-programs clone folder
WORKSPACE_PATH = os.environ['HOME'] + "/workspace/"

with open(TARGET_PATH, 'r') as f:
    targets = json.loads(f.read())['programs']

if not os.path.isdir(WORKSPACE_PATH):
    os.mkdir(WORKSPACE_PATH)

for target in targets:
    path = WORKSPACE_PATH + target['name']
    if not os.path.isdir(path):
        os.mkdir(path)

    domain_manual_path = WORKSPACE_PATH + target['name'] + '/domain_manual'
    with open(domain_manual_path, "w") as f:
        new_domains = sorted(list(set(target['domains'])))

        f.writelines("\n".join(new_domains))
