import os
import json

TARGET_PATH = os.environ['HOME']
PUBLIC_TARGET_PATH = TARGET_PATH + "/targets/chaos-bugbounty-list.json" # https://github.com/projectdiscovery/public-bugbounty-programs clone
PRIVATE_TARGET_PATH = os.environ['HOME'] + "/targets/private-list.json" # same format with https://github.com/projectdiscovery/public-bugbounty-programs

WORKSPACE_PATH = os.environ['HOME'] + "/workspace/"

def update_workspace(targets):
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


if __name__ == "__main__":
    try:
        with open(PUBLIC_TARGET_PATH, 'r') as f:
            targets = json.loads(f.read())['programs']
        update_workspace(targets)
    except:
        print("No public target")
    
    try:
        with open(PRIVATE_TARGET_PATH, 'r') as f:
            targets = json.loads(f.read())['programs']
        update_workspace(targets)
    except:
        print("No private target")
