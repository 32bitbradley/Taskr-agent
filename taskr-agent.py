import logging
#from concurrent.futures import ThreadPoolExecutor
import threading
import time
import uuid
import hashlib
import os
import time
import subprocess
from queue import Queue
import yaml
import json
import json_log_formatter
import requests

# Load configuration files
with open("config/config.yaml", mode="r") as f:
    config = yaml.safe_load(f.read())

if config == None:
    print("[Error] No config file could be loaded.")
    exit(1)

with open("config/internal_settings.yaml", mode="r") as f:
    internal_settings = yaml.safe_load(f.read())

if config == None:
    print("[Error] No internal settings file could be loaded.")
    exit(1)

# Init logging #logger.info('Example log', extra={'Example Key': 'Example Value'})
formatter = json_log_formatter.JSONFormatter()
json_handler = logging.FileHandler(filename=config['logging']['location'])
json_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(json_handler)
if config['logging']['level'] == "CRITICAL":
    logger.setLevel(logging.CRITICAL)
elif config['logging']['level'] == "ERROR":
    logger.setLevel(logging.ERROR)
elif config['logging']['level'] == "WARNING":
    logger.setLevel(logging.WARNING)
elif config['logging']['level'] == "INFO":
    logger.setLevel(logging.INFO)
elif config['logging']['level'] == "DEBUG":
    logger.setLevel(logging.DEBUG)
elif config['logging']['level'] == "NOTSET":
    logger.setLevel(logging.NOTSET)
else:
    print(f"[Error] Invalid logging level found {config['logging']['level']}. Should be one of 'CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET'.")
    exit(1)

if __name__ == '__main__':

    # Setup the agent if not already setup
    if internal_settings['agent']['status'] != "configured":
        configure_agent()

    # Create a tasks queue that will hold pending tasks
    tasks_queue = Queue(maxsize=config['tasks']['queue_size'])

    # Create and start worker threads
    for i in range(config['tasks']['workers']):
        worker = threading.Thread(target=task_worker, args=(tasks_queue))
        worker.daemon = True
        worker.start()

    # Create and start collector thread:
        task_collector = threading.Thread(target=task_collector, args=())