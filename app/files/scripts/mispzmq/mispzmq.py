#!/usr/bin/env python3
import zmq
from zmq.auth.thread import ThreadAuthenticator
from zmq.utils.monitor import recv_monitor_message
import sys
import redis
import json
import os
import time
import threading
import logging
from pathlib import Path


logging.basicConfig(level=logging.INFO, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")


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


EVENT_MAP = {}
for name in dir(zmq):
    if name.startswith("EVENT_"):
        value = getattr(zmq, name)
        EVENT_MAP[value] = name


def event_monitor(monitor, logger):
    while monitor.poll():
        evt = recv_monitor_message(monitor)
        if evt["event"] == zmq.EVENT_MONITOR_STOPPED:
            break
        evt.update({"description": EVENT_MAP[evt["event"]]})
        logger.debug("ZMQ event: {}".format(evt))
    monitor.close()


class MispZmq:
    message_count = 0
    publish_count = 0

    monitor_thread = None
    auth = None
    socket = None
    pidfile = None

    def __init__(self):
        self._logger = logging.getLogger()

        self.tmp_location = Path(__file__).parent.parent / "tmp"
        self.pidfile = self.tmp_location / "mispzmq.pid"
        if self.pidfile.exists():
            with open(self.pidfile.as_posix()) as f:
                pid = f.read()
            if check_pid(pid):
                raise Exception("mispzmq already running on PID {}".format(pid))
            else:
                # Cleanup
                self.pidfile.unlink()
        if (self.tmp_location / "mispzmq_settings.json").exists():
            self._setup()
        else:
            raise Exception("The settings file is missing.")

    def _setup(self):
        with open((self.tmp_location / "mispzmq_settings.json").as_posix()) as settings_file:
            self.settings = json.load(settings_file)
        self.namespace = self.settings["redis_namespace"]
        self.r = redis.StrictRedis(host=self.settings["redis_host"], db=self.settings["redis_database"],
                                   password=self.settings["redis_password"], port=self.settings["redis_port"],
                                   decode_responses=True)
        self.timestamp_settings = time.time()
        self._logger.debug("Connected to Redis {}:{}/{}".format(self.settings["redis_host"], self.settings["redis_port"],
                                                           self.settings["redis_database"]))

    def _setup_zmq(self):
        context = zmq.Context()

        if "username" in self.settings and self.settings["username"]:
            if "password" not in self.settings or not self.settings["password"]:
                raise Exception("When username is set, password cannot be empty.")

            self.auth = ThreadAuthenticator(context)
            self.auth.start()
            self.auth.configure_plain(domain="*", passwords={self.settings["username"]: self.settings["password"]})
        else:
            if self.auth:
                self.auth.stop()
            self.auth = None

        self.socket = context.socket(zmq.PUB)
        if self.settings["username"]:
            self.socket.plain_server = True  # must come before bind
        self.socket.bind("tcp://{}:{}".format(self.settings["host"], self.settings["port"]))
        self._logger.debug("ZMQ listening on tcp://{}:{}".format(self.settings["host"], self.settings["port"]))

        if self._logger.isEnabledFor(logging.DEBUG):
            monitor = self.socket.get_monitor_socket()
            self.monitor_thread = threading.Thread(target=event_monitor, args=(monitor, self._logger))
            self.monitor_thread.start()
        else:
            if self.monitor_thread:
                self.socket.disable_monitor()
            self.monitor_thread = None

    def _handle_command(self, command):
        if command == "kill":
            self._logger.info("Kill command received, shutting down.")
            self.clean()
            sys.exit()

        elif command == "reload":
            self._logger.info("Reload command received, reloading settings from file.")
            self._setup()
            self._setup_zmq()

        elif command == "status":
            self._logger.info("Status command received, responding with latest stats.")
            self.r.delete("{}:status".format(self.namespace))
            self.r.lpush("{}:status".format(self.namespace),
                         json.dumps({"timestamp": time.time(),
                                     "timestampSettings": self.timestamp_settings,
                                     "publishCount": self.publish_count,
                                     "messageCount": self.message_count}))
        else:
            self._logger.warning("Received invalid command '{}'.".format(command))

    def _create_pid_file(self):
        with open(self.pidfile.as_posix(), "w") as f:
            f.write(str(os.getpid()))

    def _pub_message(self, topic, data):
        self.socket.send_string("{} {}".format(topic, data))

    def clean(self):
        if self.monitor_thread:
            self.socket.disable_monitor()
        if self.auth:
            self.auth.stop()
        if self.socket:
            self.socket.close()
        if self.pidfile:
            self.pidfile.unlink()

    def main(self):
        self._create_pid_file()
        self._setup_zmq()
        time.sleep(1)

        status_array = [
            "And when you're dead I will be still alive.",
            "And believe me I am still alive.",
            "I'm doing science and I'm still alive.",
            "I feel FANTASTIC and I'm still alive.",
            "While you're dying I'll be still alive.",
        ]
        topics = ["misp_json", "misp_json_event", "misp_json_attribute", "misp_json_sighting",
                  "misp_json_organisation", "misp_json_user", "misp_json_conversation",
                  "misp_json_object", "misp_json_object_reference", "misp_json_audit",
                  "misp_json_tag",
                  ]

        lists = ["{}:command".format(self.namespace)]
        for topic in topics:
            lists.append("{}:data:{}".format(self.namespace, topic))

        while True:
            data = self.r.blpop(lists, timeout=10)

            if data is None:
                # redis timeout expired
                current_time = int(time.time())
                time_delta = current_time - int(self.timestamp_settings)
                status_entry = int(time_delta / 10 % 5)
                status_message = {
                    "status": status_array[status_entry],
                    "uptime": current_time - int(self.timestamp_settings)
                }
                self._pub_message("misp_json_self", json.dumps(status_message))
                self._logger.debug("No message received for 10 seconds, sending ZMQ status message.")
            else:
                key, value = data
                key = key.replace("{}:".format(self.namespace), "")
                if key == "command":
                    self._handle_command(value)
                elif key.startswith("data:"):
                    topic = key.split(":")[1]
                    self._logger.debug("Received data for topic '{}', sending to ZMQ.".format(topic))
                    self._pub_message(topic, value)
                    self.message_count += 1
                    if topic == "misp_json":
                        self.publish_count += 1
                else:
                    self._logger.warning("Received invalid message '{}'.".format(key))


if __name__ == "__main__":
    mzq = MispZmq()
    try:
        mzq.main()
    except KeyboardInterrupt:
        mzq.clean()
