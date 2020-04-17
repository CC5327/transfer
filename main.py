import json
import sys

from mitm import *
from receive import *
from send import *
from utils import *

if __name__ == "__main__":
    conf = load_config()
    if len(sys.argv) < 2:
        print("you must set as first argument \"send\", \"receive\" or \"mitm\"")
        exit(0)
    elif sys.argv[1] == "send":
        if len(sys.argv) != 4:
            print("send should have only two arguments: <destination> and <filename>")
            exit(0)
        send(conf, sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "receive":
        if len(sys.argv) != 4:
            print("send should have only two arguments: <port> <recv_filename>")
            exit(0)
        receive(conf, sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "mitm":
        if len(sys.argv) != 6:
            print("send should have only four arguments: <recv_port> <dest_ip> <dest_port> <recv_filename>")
            exit(0)
        mitm(conf, sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        print("the first argument can be only \"send\", \"receive\" or \"mitm\"")
        exit(1)