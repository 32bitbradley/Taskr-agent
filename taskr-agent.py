import logging
import threading
import time
import uuid
import yaml
import json_log_formatter
import schedule
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

def new_tasks():

    # Request tasks from manager via task query endpoint
    request_host = f"{config['manager']['address']}:{config['manager']['port']}"
    request_headers = {"Content_Type": "application/json", "Accept": "application/json", "Authorization": config['manager']['api_key']}
    request_params = {"target_agent_name": internal_settings['agent']['uuid'], "status_status": "pending,stopped", "expired": 'false'}

    logger.debug('Sending GET query request to the manager', extra={'request_host': request_host, 'request_headers': request_headers})
    request_response = requests.get(request_host, headers=request_headers, params=request_params)
    logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

    request_response_json = request_response.json()

    # If the request did contain tasks, add it to a list, else return an empty list.
    if len(request_response_json['data']['tasks']) > 0:
        
        print("Yes")

    else:
        logger.debug('No outstanding tasks received from the manager', extra={'tasks': request_response_json['data']['tasks']})
        return False

def cleanup_tasks():
    #
    print("Yes")

# For use with the schedule package to run schedules in paralel
def run_threaded(job_func):
    job_thread = threading.Thread(target=job_func)
    job_thread.start()

def configure_agent():

    internal_settings['agent']['uuid'] = str(uuid.uuid4())
    internal_settings['agent']['status'] = "configured"

    with open("config/internal_settings.yaml", mode="w") as settings_file:
        yaml.dump(internal_settings, settings_file)


# Setup the agent if not already setup
if internal_settings['agent']['status'] != "configured":
    configure_agent()
    
# Set the scheduled functions
#schedule.every(int(config['manager']['internal'])).seconds.do(run_threaded, new_tasks)

# Run scheduled functions loop
#while 1:
#    schedule.run_pending()
#    time.sleep(1)

