import os
import subprocess
import tempfile
import random
import argparse
import types

WORKSPACE_PATH = os.environ['HOME'] + "/workspace/"
TEMP_PATH = "/tmp/"

DAILY_DONE = './daily_done'
DAILY_NOSCAN = './daily_noscan'

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

class Modules():
    
    def subfinder(self, path):

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

    def httpx(self, path):
        command = Command('httpx', path + "/domain_daily", path + "/http_daily")

        process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
        output, error = process.communicate()

    def subtakeover(self, path):
        command = Command('nuclei', path + "/http_daily", path + "/subtakeover_daily", ['-w', '/home/op/nuclei-templates/takeovers'])
        process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
        output, error = process.communicate()

    def gospider(self, path):
        command = Command('gospider', path + "/http_daily", path + "/gospider_daily")
        process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        # extract subdomain -> save it at total domain (not domain_daily)

    def s3takeover(self, path):
        # get filenames
        try:
            spider_res_files = os.listdir(path + "/gospider_daily")
        except:
            return

        result_path = path + "/s3takeover_daily/"
        if not os.path.isdir(result_path):
            os.mkdir(result_path)

        for filename in spider_res_files:
            filepath = path + "/gospider_daily/" + filename

            # get aws-s3 url
            p1 = subprocess.Popen(["cat", filepath], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["grep", "\[aws-s3\]"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p3 = subprocess.Popen(["awk", "{ print $3 }"], stdin=p2.stdout, stdout=subprocess.PIPE)

            aws_links, error = p3.communicate()
            p3.wait()

            aws_links = list(map(lambda s: s.strip(), aws_links.decode('utf-8').splitlines()))

            # handling url started with '//'
            for index, link in enumerate(aws_links):
                if link.startswith("//"):
                    aws_links[index] = link[2:]

            with tempfile.NamedTemporaryFile(dir=TEMP_PATH, mode="w") as tf:
                if not aws_links:
                    continue

                tf.write("\n".join(aws_links))
                tf.flush()

                # check http first
                httpx_res_temp = make_tempfile_name()
                command = Command('httpx', tf.name, httpx_res_temp)
                process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
                _, _ = process.communicate()

                command = Command('nuclei', httpx_res_temp, result_path + filename, ['-w', '/home/op/nuclei-templates/takeovers/aws-bucket-takeover.yaml'])
                process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
                output, error = process.communicate()
                # print(output.decode('utf-8'))

                rm_tmpfile(httpx_res_temp)

    def exposed_token(self, path):
        # get filenames
        try:
            spider_res_files = os.listdir(path + "/gospider_daily")
        except:
            return

        result_path = path + "/exposed_token_daily/"
        if not os.path.isdir(result_path):
            os.mkdir(result_path)

        for filename in spider_res_files:
            filepath = path + "/gospider_daily/" + filename

            # get javascript
            p1 = subprocess.Popen(["cat", filepath], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["grep", "\[javascript\]"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p3 = subprocess.Popen(["awk", "{ print $3 }"], stdin=p2.stdout, stdout=subprocess.PIPE)

            js_links, error = p3.communicate()
            p3.wait()

            # get live links
            p1 = subprocess.Popen(["cat", filepath], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["grep", "\[url\]"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p3 = subprocess.Popen(["awk", "{ print $5 }"], stdin=p2.stdout, stdout=subprocess.PIPE)

            live_links, error = p3.communicate()
            p3.wait()

            with tempfile.NamedTemporaryFile(dir=TEMP_PATH) as tf:
                tf.write(live_links)
                tf.write(js_links)
                tf.flush()

                command = Command('nuclei', tf.name, result_path + filename, ['-w', '/home/op/nuclei-templates/exposed-tokens'])
                process = subprocess.Popen(command.aslist(), stdout=subprocess.PIPE)
                output, error = process.communicate()

def make_tempfile_name():
    return TEMP_PATH + "axiom_tmp" + str(random.randint(0, 100000000))

def rm_tmpfile(path):
    try:
        os.remove(path)
    except OSError:
        print("No tempfile at " + path)

def scan(path, modules):
    # scan_object = Modules()
    # for module in modules:
    #     method = getattr(scan_object, module)
    #     method(path)

    # Call manually To keep module order
    scan_object = Modules()
    if "subfinder" in modules:
        scan_object.subfinder(path)
    if "httpx" in modules:
        scan_object.httpx(path)
    if "gospider" in modules:
        scan_object.gospider(path)
    if "subtakeover" in modules:
        scan_object.subtakeover(path)
    if "s3takeover" in modules:
        scan_object.s3takeover(path)
    if "exposed_token" in modules:
        scan_object.exposed_token(path)

def get_module_names():
    result = []
    for attr, val in Modules.__dict__.items():
        if type(val) == types.FunctionType:
            result.append(attr)
    return result

        exposed_token(path)

if __name__ == '__main__':
    module_list = get_module_names()

    parser = argparse.ArgumentParser(description='Process some integers.')

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-t', '--target', help='Select one target')
    target_group.add_argument('-c', '--cont', action='store_true', help='Continue daily scan')

    module_group = parser.add_mutually_exclusive_group(required=True)
    module_group.add_argument('-m', '--modules', nargs='+', help='Select modules to use', choices=module_list)
    module_group.add_argument('-a', '--all', action='store_true', help='Use all modules')

    args = parser.parse_args()

    targets = []
    done = []
    noscan = []

    if args.target:
        targets = [args.target]
    elif args.cont:
        try:
            with open(DAILY_DONE, 'r') as f:
                done = f.readlines()
                done = list(map(lambda s: s.strip(), done))
        except:
            pass

        targets = os.listdir(WORKSPACE_PATH)
        targets = list(set(targets) - set(done))

        try:
            with open(DAILY_NOSCAN, 'r') as f:
                noscan = f.readlines()
                noscan = list(map(lambda s: s.strip(), noscan))
        except:
            pass

        targets = list(set(targets) - set(noscan))

    if args.modules:
        modules = args.modules
    elif args.all:
        modules = module_list


    for target in targets:
        path = WORKSPACE_PATH + target
        if not os.path.isdir(path):
            continue

        scan(path, modules)

        if args.cont:
            with open('daily_done', 'a') as f:
                f.write(target + '\n')
