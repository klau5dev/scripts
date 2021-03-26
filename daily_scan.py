import os
import subprocess
# import tempfile
import random

WORKSPACE_PATH = os.environ['HOME'] + "/workspace/"
TEMP_PATH = "/tmp/"

class Command():
    def __init__(self, module, input_path, output_path, options=None):
        self.module = module
        self.input_path = input_path
        self.output_path = output_path

        if options == None:
            options = []
        self.options = options

    def aslist(self):
        return [
            'axiom-scan',
            self.input_path,
            '-m',
            self.module,
            '-o',
            self.output_path
        ] + self.options

def merge_result(result1, result2):
    if type(result1) != type(result2):
        raise Exception

    if isinstance(result1, list):
        result = sorted(list(set(result1 + result2)))
    return result

def subfinder(path):

    manual_temp = make_tempfile_name()

    command = Command('subfinder', path + "/domain_manual", manual_temp)

    process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    with open(manual_temp, 'r') as f:
        manual_result = f.readlines()
        manual_result = list(map(lambda s: s.strip(), manual_result))

    rm_tmpfile(manual_temp)

    # If daily scan result exist, use this as seed data and scan
    try:
        with open(path + '/domain_daily') as f:
            old_result = f.readlines()
            old_result = list(map(lambda s: s.strip(), old_result))

        daily_temp = make_tempfile_name()

        command = Command('subfinder', path + "/domain_daily", daily_temp)

        process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        with open(daily_temp, 'r') as f:
            daily_result = f.readlines()
            daily_result = list(map(lambda s: s.strip(), daily_result))

        daily_result = merge_result(old_result, daily_result)

        rm_tmpfile(daily_temp)

    except IOError:
        daily_result = None

    # merge result
    if daily_result != None:
        result = merge_result(manual_result, daily_result)
    else:
        result = manual_result

    with open(path + '/domain_daily', "w") as f:
        f.writelines("\n".join(result))

def httpx(path):
    command = Command('httpx', path + "/domain_daily", path + "/http_daily")

    process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
    output, error = process.communicate()

def subtakeover(path):
    command = Command('nuclei', path + "/http_daily", path + "/subtakeover_daily", ['-w', '/home/op/nuclei-templates/takeovers'])
    process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
    output, error = process.communicate()

def make_tempfile_name():
    return TEMP_PATH + "axiom_tmp" + str(random.randint(0, 100000000))

def rm_tmpfile(path):
    try:
        os.remove(path)
    except OSError:
        print("No tempfile at " + path)

if __name__ == '__main__':
    dirs = os.listdir(WORKSPACE_PATH)

    for target in dirs:
        path = WORKSPACE_PATH + target
        if not os.path.isdir(path):
            continue

        subfinder(path)
        httpx(path)
        subtakeover(path)

        break

