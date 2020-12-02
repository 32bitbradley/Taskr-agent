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

def query_for_tasks():
    """Will query the manager for outstanding tasks for this agent

    Params:

    Returns:
        A list of task dictionaries
    """

    # Request tasks from manager via task query endpoint
    request_host = f"{config['manager']['address']}:{config['manager']['port']}/api/task"
    request_headers = {"Accept": "application/json"}
    request_params = {"target_agent": internal_settings['agent']['uuid'], "status_status": "pending,stopped", "expiration_expired": 'false'}

    logger.debug('Sending GET query request to the manager', extra={'request_host': request_host, 'request_headers': request_headers})
    request_response = requests.get(request_host, headers=request_headers, params=request_params)
    logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

    request_response_json = request_response.json()

    if request_response.status_code == 200:


        # If the request did contain tasks, add it to a list, else return an empty list.
        if len(request_response_json['data']['results']) > 0:
            
            data = []

            for task in request_response_json['data']['results']:
                data.append(task)

            return data

        else:
            logger.debug('No outstanding tasks received from the manager', extra={'tasks': request_response_json['data']['results']})
            data = []
            return data

    else:
        logger.error('The manager did not respond with 200 when querying for tasks', extra={'tasks': request_response_json['data']['results']})
        data = []
        return data

def get_task_type(type_id):
    """Will query the manager for task type information fro a given task type id

    Params:
        type_id: The task type id to query for

    Returns:
        Either a a dictonary of type information, or False of unsuccessful
    """

    # Request tasks from manager via task query endpoint
    request_host = f"{config['manager']['address']}:{config['manager']['port']}/api/type/{type_id}"
    request_headers = {"Accept": "application/json"}

    logger.debug('Sending GET query request to the manager', extra={'request_host': request_host, 'request_headers': request_headers})
    request_response = requests.get(request_host, headers=request_headers)
    logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

    request_response_json = request_response.json()

    if request_response.status_code == 200:

        # If the request did contain tasks, add it to a list, else return an empty list.
        if len(request_response_json['data']['results']) == 1:

            logger.debug('The manager did return a task', extra={'tasks': request_response_json['data']['tasks']})
            return request_response_json['data']['results'][0]

    else:
        logger.error('The manager did not return 1 task', extra={'tasks': request_response_json['data']['tasks']})
        return False

def get_task(task_id):
    """Get a specific task from the manager

    Params:
        task_id: The ID of the task to update

    Returns:
        * A dictionary of task details
    """
    # Request tasks from manager via task query endpoint
    request_host = f"{config['manager']['address']}:{config['manager']['port']}/api/task/{task_id}"
    request_headers = {"Accept": "application/json"}

    logger.debug('Sending GET query request to the manager', extra={'request_host': request_host, 'request_headers': request_headers})
    request_response = requests.get(request_host, headers=request_headers)
    logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

    request_response_json = request_response.json()

    if request_response.status_code == 200:


        # If the request did contain tasks, add it to a list, else return an empty list.
        if len(request_response_json['data']['results']) == 1:
            
            data = request_response_json['data']['results'][0]

            return data

        elif len(request_response_json['data']['results']) == 0:
            logger.debug('No outstanding tasks received from the manager', extra={'tasks': request_response_json['data']['results']})
            data = {}
            return data

        else:
            logger.error('The manager responded with more than 1 task for a specific task ID', extra={'tasks': request_response_json['data']['results']})
            data = {}
            return data
    else:
        logger.error('The manager did not respond with 200 when querying for tasks', extra={'tasks': request_response_json['data']['results']})
        data = {}
        return data

def update_task(task_id, task_status, task_output):
    """Will update a task status on the manager using the provided info

    Params:
        task_id: The ID of the task to update
        task_status: The exist status of the task, either [completed, failed]
        task_output: A dictionary to be passwd as the task output

    Returns:
        True if successful
        False if failed or error
    """

    existing_task_details = get_task(task_id)

    if len(existing_task_details) == 0:
        return False


    updated_task_details = existing_task_details
    updated_task_details['status']['status'] = task_status
    updated_task_details['response'] = task_output

    # Request tasks from manager via task query endpoint
    request_host = f"{config['manager']['address']}:{config['manager']['port']}/api/task/{task_id}"
    request_headers = {"Accept": "application/json"}

    logger.debug('Sending GET query request to the manager', extra={'request_host': request_host, 'request_headers': request_headers})
    request_response = requests.patch(request_host, headers=request_headers, json=updated_task_details)
    logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

    request_response_json = request_response.json()

    if request_response.status_code == 200:

        logger.debug('Task updated successfully', extra={'request_response_json': request_response_json})
        return True

    else:
        logger.error('The manager did not respond with 200 when updating task', extra={'request_response_json': request_response_json})
        return False
        
def check_running_tasks():
    """Will return a list of running task threads

    Params:

    Returns:
        current_task_threads: A list of dictionaries contained task info
    """

    current_task_threads = []

    for thread in threading.enumerate():

        if str(thread.name).startswith("task__"):

            logger.debug('Found a running task thread', extra={'thread_name': str(thread.name)})
            task_details = {}
            task_details['name'] = str(thread.name)
            
            current_task_threads.append(task_details)

    return current_task_threads

def check_bin( type_bin_name, type_bin_hash):
    """Will check if a bin file exists on the syste and if the sha256 sum katches the one provided by the manager

    Params:
        type_bin_name: The name of the file to check
        type_bin_hash: The hash of the file, as reported by the manager to verify the file.

    Returns:
        * True if successfull
        * False if unsuccessfull
    """

    if os.path.isfile(f"types/{type_bin_name}"):
        logger.debug('Task type bin file exists on the system', extra={'type_bin_name': type_bin_name})

        existing_file_sha256_hash = hashlib.sha256()

        with open(f"types/{type_bin_name}","rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096),b""):
                existing_file_sha256_hash.update(byte_block)

        if str(existing_file_sha256_hash.hexdigest()) == str(type_bin_hash):
            logger.debug('The existing bin file is at the latest version', extra={'type_bin_name': type_bin_name, 'hash':existing_file_sha256_hash})
            return True
        else:
            logger.debug('The existing bin file is not latest version', extra={'type_bin_name': type_bin_name, 'hash':existing_file_sha256_hash})
            return False
    else:
        logger.debug('Task type bin file does not exist on the system', extra={'type_bin_name': type_bin_name})
        return False

def download_bin(type_id, type_bin_name, type_bin_hash):
    """Will download the task bin file from the manager, and the check it using the provided sha256

    Params:
        type_id: The ID of thr task type to download
        task_bin_name: The name of the file to save as
        type_bin_bash: The hash of the file to verify against as proivided by the manager

    Retruns:
        * True if successful
        * False if unsuccessful
    """

    #Delete the file if it already exists
    if os.path.isfile(f"types/{type_bin_name}"):
        logger.debug('Task type bin file exists on the system, deleting', extra={'type_bin_name': type_bin_name})
        os.remove(f"types/{type_bin_name}")

    else:

        # Request task type bin from manager via task type download endpoint
        request_host = f"{config['manager']['address']}:{config['manager']['port']}/api/type/download/{type_id}"
        request_headers = {"Accept": "*/*"}
        logger.debug('Sending GET query request to the manager', extra={'request_host': request_host, 'request_headers': request_headers})
        request_response = requests.get(request_host, headers=request_headers)
        logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

        # We might get a JSON response if something went wrong, so just check here, log and return false
        if request_response.is_json():
            request_response_json = request_response.json()
            logger.debug('Received JSON response from manager rather than a file when downloading type bin', extra={'type_id': type_id, 'json':request_response_json})
            return False
        else:
            if request_response.status_code == 200:
                # Save the downaloded file to the types dir then check the hash matches
                with open(f'types/{type_bin_name}', 'wb') as target_file:
                    target_file.write(request_response.content)

                # Generate SHA256 sum for the bin file
                logger.debug('Generating SHA256 hash for bin', extra={'bin':type_bin_name})

                target_file_sha256_hash = hashlib.sha256()

                with open(f"types/{type_bin_name}","rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096),b""):
                        target_file_sha256_hash.update(byte_block)
                    
                logger.debug('Generated SHA256 hash', extra={'hash':target_file_sha256_hash.hexdigest()})

                if str(target_file_sha256_hash.hexdigest()) == str(type_bin_hash):
                    logger.debug('Generated SHA256 hash and provided SHA256 hash match. Download successfull', extra={'file_hash':target_file_sha256_hash.hexdigest()})
                    return True
                else:
                    logger.debug('Generated SHA256 hash and provided SHA256 hash didnt match. Download not successfull', extra={'file_hash':target_file_sha256_hash.hexdigest()})
                    return False
            elif request_response.status_code == 404:
                    logger.debug('Requesting a bin to download that did not exist, got 404', extra={'type_id':type_id})
                    return False
            else:
                    logger.debug('Error when dowloading bin', extra={'type_id':type_id})
                    return False

def spawn_subprocess_task(task_id, bin_name, input_type, paramaters, output_type):
    """Will spawn a a subprocess based task using the provided task details, then will update the task's status on the manager as required.

    Params:
        task_id: The ID of the task , as assigned by the manager
        bin_name: The name of the bin file
        input_type: The input
        paramaters: A dictionary of paramaters to use as inputs
        output_type: The type of output

    Returns:
        * True if successful
        * False if error
    """
    # Create initial subprocess args list
    process = [f'types/{bin_name}']

    # Process input paramaters
    if input_type == "cli":
        logger.debug('The input type is CLI, checking paramaters dict', extra={'task_id':task_id,'paramaters':paramaters})

        # Make sure paramaters is a single depth dictionary, error if not dict and change deppers keys to JSPON strings instead.
        task_paramaters = paramaters

        if isinstance(paramaters, dict):

            for key in paramaters.keys():

                if isinstance(paramaters[key], dict):

                    logger.debug('The provided dictionary has embedded keys, converting seccond depth value to JSON string', extra={'task_id':task_id, 'key':key,'paramaters':paramaters})
                    task_paramaters[key] = json.dumps(paramaters[key])

            logger.debug('The paramaters dict as been compiled', extra={'task_id':task_id, 'task_paramaters':task_paramaters})
        
            # Build rest of subprocess args list
            for key in task_paramaters:

                process.append(str(key))
                process.append(task_paramaters[key])

            logger.debug('Process argument list is', extra={'task_id':task_id,'process':process})

            # Run basic subprocess
            process_run = subprocess.run(process, capture_output=True)

        else:
            logger.debug('The provided task paramaters is not a dictionary', extra={'task_id':task_id,'paramaters':paramaters})
            return False
    else:
        logger.error('Invalid input type', extra={'task_id':task_id, 'paramaters':paramaters})
        return False

    # Once subprocess has completed, parse any output and build a status dict

    process_output = {}
    process_output['meta'] = {}

    if process_run.returncode == 0:
        process_output['meta']['successful'] = True
        process_output['meta']['retun_code'] = process_run.returncode
        task_status = "completed"
    else:
        process_output['meta']['successful'] = False
        process_output['meta']['retun_code'] = process_run.returncode
        task_status = "failed"

    process_output['stderr'] = process_run.stderr
    process_output['stdout'] = process_run.stdout

    if output_type == "stdout":
        process_output['output'] = process_run.stdout
    else:
        logger.error('Invalid output type when compiling resuts', extra={'task_id':task_id,'output_type':output_type})

    # Update the task's status on the manager with the process_output
    if update_task(task_id, task_status, process_output):
        logger.debug('Task execution process completed successfully', extra={'task_id':task_id})
        return True
    else:
        logger.debug('Task execution process did not complete successfully', extra={'task_id':task_id})
        return False

def configure_agent():

    internal_settings['agent']['uuid'] = str(uuid.uuid4())
    internal_settings['agent']['status'] = "configured"

    with open("config/internal_settings.yaml", mode="w") as settings_file:
        yaml.dump(internal_settings, settings_file)

def task_collector():
    """Query for tasks on a scheudle, and add the the task queue. Will run on a endless loop.
    """
    while True:
        # Query manager for tasks if the tasks queue is not full
        if tasks_queue.full() == False:
            logger.debug('Task queue is not full, collector is querying for tasks')
            received_tasks = query_for_tasks()

            if len(received_tasks) > 0:
                logger.debug('Collector received a list of tasks', extra={'received_tasks':received_tasks})

                for task in received_tasks:
                    if tasks_queue.full() == False:
                        tasks_queue.put(task)
                        logger.debug('Collector added a task to the task queue', extra={'task':task})
                        if update_task(task['task']['id'], "queued", None):
                            logger.debug('Collector successfully updated task status to pending', extra={'task':task})
                        else:
                            logger.error('Collector thread could not update task status to pending', extra={'task':task})
                    else:
                        logger.debug('Task queue is now full, not adding any more tasks to the queue', extra={'task':task})

            # If Task queue is not full add to queue
        else:
            logger.debug('Task queue is full, collector is not querying for tasks')

        # Wait for the sepcificed delay in the config file
        time.sleep(int(config['tasks']['interval']))

def task_worker(tasks_queue):
    """Monitor tasks queue and execute tasks as appropriate
    """
    while True:
        # Get task from queue if not empty
        if tasks_queue.empty() == False:
            logger.debug('Task is not empty, worker is getting a task', extra={'thread_id':str(threading.get_ident())})
            new_task = tasks_queue.get()
            # launch as needed type
            if spawn_subprocess_task(new_task['task']['id'], new_task['bin']['name'], new_task['bin']['input'], new_task['parameters'], new_task['bin']['output']):
                logger.debug('Task execution completed successfully, marking task as done in queue as manager should have bene updated already.', extra={'task':new_task, 'thread_id':str(threading.get_ident())})
            else:
                logger.debug('Task execution did not complete successfully, marking task as done in queue as manager should have bene updated already.', extra={'task':new_task, 'thread_id':str(threading.get_ident())})
            # Complete task
            tasks_queue.task_done()
        else:
            queue_delay = 1
            logger.debug('Task is empty, not starting a new task yet.', extra={'thread_id':str(threading.get_ident()), 'sleep':queue_delay})
            time.sleep(queue_delay)

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
        collector = threading.Thread(target=task_collector, args=())
        collector.daemon = True
        collector.start()