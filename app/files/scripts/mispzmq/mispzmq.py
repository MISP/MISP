#!/usr/bin/env python3

import zmq
import sys
import redis
import json
import os
import time

from pathlib import Path


def check_pid(pid):
    """ Check For the existence of a unix pid. """
    if not pid:
        return False
    pid = int(pid)

    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


class MISPZMQ():

    def __init__(self):
        self.current_location = Path(__file__).parent
        self.pidfile = self.current_location / "mispzmq.pid"
        self.publishCount = 0
        if self.pidfile.exists():
            with open(self.pidfile.as_posix()) as f:
                pid = f.read()
            if check_pid(pid):
                raise Exception('mispzmq already running on PID {}'.format(pid))
            else:
                # Cleanup
                self.pidfile.unlink()
        if (self.current_location / 'settings.json').exists():
            self.setup()
        else:
            raise Exception("The settings file is missing.")

    def setup(self):
        with open((self.current_location / 'settings.json').as_posix()) as settings_file:
            self.settings = json.load(settings_file)
        self.namespace = self.settings["redis_namespace"]
        self.r = redis.StrictRedis(host=self.settings["redis_host"], db=self.settings["redis_database"],
                                   password=self.settings["redis_password"], port=self.settings["redis_port"],
                                   decode_responses=True)
        self.timestampSettings = time.time()

    def handleCommand(self, command):
        if command == "kill":
            print("Kill command received, shutting down.")
            self.pidfile.unlink()
            sys.exit()
        if command == "reload":
            print("Reload command received, reloading settings from file.")
            self.setup()
        if command == "status":
            print("Status command received, responding with latest stats.")
            self.r.delete("{}:status".format(self.namespace))
            self.r.lpush("{}:status".format(self.namespace),
                         json.dumps({"timestamp": time.time(),
                                     "timestampSettings": self.timestampSettings,
                                     "publishCount": self.publishCount}))

    def createPidFile(self):
        with open(self.pidfile.as_posix(), 'w') as f:
            f.write(str(os.getpid()))

    def pubMessage(self, topic, data, socket):
        socket.send_string("{} {}".format(topic, data))
        if topic is 'misp_json':
            self.publishCount += 1

    def main(self):
        start_time = int(time.time())
        self.createPidFile()
        status_array = [
            "And when you're dead I will be still alive.",
            "And believe me I am still alive.",
            "I'm doing science and I'm still alive.",
            "I feel FANTASTIC and I'm still alive.",
            "While you're dying I'll be still alive."
        ]
        context = zmq.Context()
        socket = context.socket(zmq.PUB)
        socket.bind("tcp://*:{}".format(self.settings["port"]))
        time.sleep(1)

        while True:
            command = self.r.lpop("{}:command".format(self.namespace))
            if command is not None:
                self.handleCommand(command)
            topics = ["misp_json", "misp_json_event", "misp_json_attribute", "misp_json_sighting",
                      "misp_json_organisation", "misp_json_user", "misp_json_conversation",
                      "misp_json_object", "misp_json_object_reference", "misp_json_audit",
                      "misp_json_tag"
                      ]
            message_received = False
            for topic in topics:
                data = self.r.lpop("{}:data:{}".format(self.namespace, topic))
                if data is not None:
                    self.pubMessage(topic, data, socket)
                    message_received = True
            if not message_received:
                time.sleep(0.1)
            current_time = 10 * time.time()
            temp_start_time = 10 * start_time
            time_delta = int(current_time - temp_start_time)
            if (time_delta % 100 == 0):
                status_entry = int(time_delta / 100 % 5)
                status_message = {
                    'status': status_array[status_entry],
                    'uptime': int(time.time()) - start_time
                }
                self.pubMessage('misp_json_self', json.dumps(status_message), socket)


if __name__ == "__main__":
    mzq = MISPZMQ()
    mzq.main()
