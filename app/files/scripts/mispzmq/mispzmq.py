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
        print "Kill command received, shutting down.\n"
        removePidFile()
        sys.exit()
    if command == "reload":
        print "Reload command received, reloading settings from file.\n"
        setup()
    if command == "status":
        print "Status command received, responding with latest stats.\n"
        r.delete(namespace + ":status")
        r.lpush(namespace + ":status", json.dumps({"timestamp": timestamp, "timestampSettings": timestampSettings, "publishCount": publishCount}))
    return

def removePidFile():
    os.unlink(pidfile)

def createPidFile():
    pid = str(os.getpid())
    file(pidfile, 'w').write(pid)

def pubMessage(data):
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind("tcp://*:%s" % settings["port"])
    print "Sending " + data
    time.sleep(1)
    socket.send("%s %s" % ('misp_json', data))
    socket.close()
    context.term()
    global publishCount
    publishCount = publishCount + 1

def main(args):
    setup()
    createPidFile()
    while True:
        time.sleep(1)
        command = r.lpop(namespace + ":command")
        if command is not None:
            handleCommand(command)
        topic = "misp_json"
        data = r.lpop(namespace + ":misp_json")
        if data is None:
            continue
        pubMessage(data)

if __name__ == "__main__":
    main(sys.argv)
