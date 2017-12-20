import zmq
import sys
import redis
import json
import os
import time

socket = None
r = None
namespace = None
settings = None
current_location = os.path.dirname(os.path.realpath(__file__))
pidfile = current_location + "/mispzmq.pid"
timestamp = time.time()
timestampSettings = timestamp
publishCount = 0

def setup():
    global namespace
    global socket
    global r
    global settings
    global timestampSettings
    with open(current_location + '/settings.json') as settings_file:
        settings = json.load(settings_file)
    namespace = settings["redis_namespace"]
    r = redis.StrictRedis(host=settings["redis_host"], db=settings["redis_database"], password=settings["redis_password"], port=settings["redis_port"])
    timestampSettings = time.time()

def handleCommand(command):
    if command == "kill":
        print("Kill command received, shutting down.\n")
        removePidFile()
        sys.exit()
    if command == "reload":
        print("Reload command received, reloading settings from file.\n")
        setup()
    if command == "status":
        print("Status command received, responding with latest stats.\n")
        r.delete(namespace + ":status")
        r.lpush(namespace + ":status", json.dumps({"timestamp": timestamp, "timestampSettings": timestampSettings, "publishCount": publishCount}))
    return

def removePidFile():
    os.unlink(pidfile)

def createPidFile():
    pid = str(os.getpid())
    open(pidfile, 'w').write(pid)

def pubMessage(topic, data, socket):
    socket.send_string("%s %s" % (topic, data))
    if topic is 'misp_json':
        global publishCount
        publishCount = publishCount + 1

def main(args):
    start_time = int(time.time())
    setup()
    createPidFile()
    status_array = [
        'And when you\'re dead I will be still alive.',
        'And believe me I am still alive.',
        'I\'m doing science and I\'m still alive.',
        'I feel FANTASTIC and I\'m still alive.',
        'While you\'re dying I\'ll be still alive.'

    ]
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind("tcp://*:%s" % settings["port"])
    time.sleep(1)

    while True:
        command = r.lpop(namespace + ":command")
        if command is not None:
            handleCommand(command)
        topics = ["misp_json", "misp_json_event", "misp_json_attribute", "misp_json_sighting",
                  "misp_json_organisation", "misp_json_user", "misp_json_conversation",
                  "misp_json_object", "misp_json_object_reference", "misp_json_audit"]
        message_received = False
        for topic in topics:
            data = r.lpop(namespace + ":data:" + topic)
            if data is not None:
                pubMessage(topic, data, socket)
                message_received = True
        if (message_received == False):
            time.sleep(0.1)
        current_time = 10*time.time()
        temp_start_time = 10*start_time
        time_delta = int(current_time - temp_start_time)
        if (time_delta % 100 == 0):
            status_entry = time_delta/100 % 5
            status_message = {
                'status': status_array[status_entry],
                'uptime': int(time.time()) - start_time
            }
            pubMessage('misp_json_self', json.dumps(status_message), socket)

if __name__ == "__main__":
    main(sys.argv)
