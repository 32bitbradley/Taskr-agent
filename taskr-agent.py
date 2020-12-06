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
import signal
import yaml
import json
import json_log_formatter
import requests
from task import Query, Task

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

try:
    logger.setLevel(getattr(logging,str(config['logging']['level']).upper()))
except:
    logging.NOTSET

def configure_agent():

    internal_settings['agent']['uuid'] = str(uuid.uuid4())
    internal_settings['agent']['status'] = "configured"

    with open("config/internal_settings.yaml", mode="w") as settings_file:
        yaml.dump(internal_settings, settings_file)

def task_collector():
    """Query for tasks on a scheudle, and add the the task queue. Will run on a endless loop.
    """
    while not stop_threads.is_set():
        logger.debug("Stop threads is not set, running worker...", extra={'thread_name':collector.name, 'thread_id':threading.get_ident()})
        # Query manager for tasks if the tasks queue is not full
        if tasks_queue.full() == False:
            logger.debug('Task queue is not full, collector is querying for tasks')
            
            query = Query(config['manager']['address'], config['manager']['port'], internal_settings['agent']['uuid'])

            pending_tasks = query.query_for_tasks()

            if len(pending_tasks) > 0:
                logger.debug('Collector received a list of tasks', extra={'pending_tasks':pending_tasks})

                for task in pending_tasks:

                    if tasks_queue.full() == False:
                        tasks_queue.put(task['task']['id'])
                        logger.debug('Collector added a task to the task queue', extra={'task':task})
                        logger.info('A task has been added to the queue', extra={'task_id':task['task']['id']})

                        if query.update_task(task['task']['id'], "queued", None):
                            logger.debug('Collector successfully updated task status to queued', extra={'task':task})
                        else:
                            logger.error('Collector thread could not update task status to pending', extra={'task':task})
                    else:
                        logger.debug('Task queue is now full, not adding any more tasks to the queue', extra={'task':task})
            else:
                logger.debug('Manager did not respond with any tasks to add to the queue', extra={})
            # If Task queue is not full add to queue
        else:
            logger.info("Task queue is full", extra={'queue_max_size':config['tasks']['queue_size']})
            logger.debug('Task queue is full, collector is not querying for tasks', extra={'queue_max_size':config['tasks']['queue_size']})

        # Wait for the sepcificed delay in the config file
        time.sleep(int(config['tasks']['interval']))

def task_worker():
    """Monitor tasks queue and execute tasks as appropriate
    """
    while not stop_threads.is_set():
        logger.debug("Stop threads is not set, running worker...", extra={'thread_name':worker.name, 'thread_id':threading.get_ident()})
        # Get task from queue if not empty
        if tasks_queue.empty() == False:

            logger.debug('Task is not empty, worker is getting a task', extra={'thread_name':worker.name})

            task_id = tasks_queue.get()

            # Build task object
            task = Task(config['manager']['address'], config['manager']['port'], task_id)
            logger.debug('Created task object', extra={'task_id':task_id, 'thread_name':worker.name})

            # Execute Task
            logger.info("Executing task", extra={'task_id':task_id})
            if task.execute():
                logger.debug('Task executed successfully', extra={'task_id':task_id, 'thread_name':worker.name})
                logger.info("Task executed successfully", extra={'task_id':task_id})
                tasks_queue.task_done()

            else:
                logger.debug('Task execution did not complete successfully, marking task as done in queue as Task object should have bene updated already.', extra={'task_id':task_id, 'thread_name':worker.name})
                logger.info("Task did not execute successfully", extra={'task_id':task_id})
                tasks_queue.task_done()

        else:
            queue_delay = 1
            logger.debug('Task queue is empty, not starting a new task yet.', extra={'thread_name':worker.name, 'sleep':queue_delay})
            time.sleep(queue_delay)

# signal handler
def handle_stop(signum, frame):

    logger.info('Received SIGINT (CTRL + C) signal, stopping threads and process gracefully.')
    stop_threads.set()

    exit(0)


if __name__ == '__main__':
    # Register signal handlers 
    # `SIGINT`(CTRL + C)
    signal.signal(signal.SIGINT, handle_stop)

    # Setup the agent if not already setup
    if internal_settings['agent']['status'] != "configured":
        configure_agent()

    # Create a tasks queue that will hold pending tasks
    tasks_queue = Queue(maxsize=config['tasks']['queue_size'])

    #Create thread stop event
    stop_threads = threading.Event()

    # Create and start collector thread:
    collector = threading.Thread(target=task_collector, args=(), name=f"taskr_collector")
    collector.daemon = True
    collector.start()

    # Create and start worker threads
    for i in range(config['tasks']['workers']):
        worker = threading.Thread(target=task_worker, args=(), name=f"taskr_worker")
        worker.daemon = True
        worker.start()

    process_starttime = time.time()
    logger.info("Started taskr-agent.", extra={'uptime':str(time.time() - process_starttime), 'pid':str(os.getpid())})

    while True:
        time.sleep(10)
        logger.info("Heartbeat...", extra={'uptime':str(time.time() - process_starttime), 'pid':str(os.getpid())})
