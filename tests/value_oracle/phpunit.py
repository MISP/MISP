"""Runs one of the app/Test oracle captures. They boot the application in
their own PHPUnit process, read a JSON request named by an environment
variable and write their result to the request's "out" path."""

import json
import os
import subprocess
import tempfile
import time


def run(app_dir, test_file, env_var, request):
    """Returns (exit code, output, result or None, started, finished)."""
    with tempfile.TemporaryDirectory() as tmp:
        request = dict(request, out=os.path.join(tmp, 'result.json'))
        request_file = os.path.join(tmp, 'request.json')
        with open(request_file, 'w') as f:
            json.dump(request, f)
        started = time.time()
        proc = subprocess.run(
            [os.path.join(app_dir, 'Vendor', 'bin', 'phpunit'),
             os.path.join(app_dir, test_file)],
            env=dict(os.environ, **{env_var: request_file}),
            capture_output=True, text=True)
        finished = time.time()
        result = None
        if os.path.exists(request['out']):
            with open(request['out']) as f:
                result = json.load(f)
        return (proc.returncode, proc.stdout + proc.stderr, result, started,
                finished)
