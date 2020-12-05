import logging
import yaml
import hashlib
import os
import subprocess
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

logger = logging.getLogger()
try:
    logger.setLevel(getattr(logging,str(config['logging']['level']).upper()))
except:
    logging.NOTSET

class Query:

    def __init__(self, manager_address, manager_port, agent_uuid):
        
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.agent_uuid = agent_uuid

        self.host_base = f"http://{manager_address}:{manager_port}/api"
        self.request_headers = {"Accept": "application/json"}
        
    def query_for_tasks(self):
        """Will query the manager for outstanding tasks for this agent

        Params:

        Returns:
            A list of task dictionaries or en empty list
        """

        # Request tasks from manager via task GET endpoint using query parameters
        self.request_host = self.host_base + f"/task"

        logger.debug('Sending GET query request to the manager', extra={'request_host': self.request_host, 'request_headers': self.request_headers})

        self.request_params = {"target_agent": self.agent_uuid, "status_status": "pending,stopped", "expiration_expired": 'false'}

        request_response = requests.get(self.request_host, headers=self.request_headers, params=self.request_params)

        logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

        request_response_json = request_response.json()

        if request_response.status_code == 200:


            # If the request did contain tasks, add it to a list, else return an empty list.
            if len(request_response_json['data']['results']) > 0:

                logger.debug('Outstanding tasks have been received from the manager', extra={'tasks': request_response_json['data']['results']})
                
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

    def get_task(self, task_id):
        """Get a specific task from the manager

        Params:
            task_id: The ID of the task to update

        Returns:
            * A single dictionary of 1 task's details
        """
        # Request tasks from manager via task query endpoint
        self.task_id = task_id
        self.task_details = {}

        self.request_host = self.host_base + f"/task/{self.task_id}"
        logger.debug('Sending GET query request to the manager', extra={'request_host': self.request_host, 'request_headers': self.request_headers})
        request_response = requests.get(self.request_host, headers=self.request_headers)

        if request_response.status_code == 200:

            logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})
            request_response_json = request_response.json()

            # If the request did contain a single task, add it to a list, else return an empty list.
            if len(request_response_json['data']['results']) == 1:
                
                logger.debug('Received 1 task from the manager', extra={'results': request_response_json['data']['results']})
                
                self.task_details = request_response_json['data']['results'][0]
                return self.task_details

            elif len(request_response_json['data']['results']) == 0:

                logger.debug('The manager did not respond with a task for that ID', extra={'tasks': request_response_json['data']['results'], 'task_id':self.task_id, 'request_host':self.request_host})

                return {}

            else:

                logger.error('The manager responded with more than 1 task for a specific task ID', extra={'tasks': request_response_json['data']['results']})

                return {}
        else:

            logger.error('The manager did not respond with 200 when querying for tasks', extra={'tasks': request_response_json['data']['results']})
            
            return {}

    def get_type(self, type_id):
        """Will query the manager for a specific task type.

        Params:
            type_id: The task type id to query for

        Returns:
            A dictionary of task information
        """
        self.type_id = type_id
        self.type_details = {}
        self.request_host = self.host_base + f"/type/{self.type_id}"

        logger.debug('Sending GET query request to the manager', extra={'request_host':  self.request_host, 'request_headers': self.request_headers})

        request_response = requests.get(self.request_host, headers=self.request_headers)

        logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

        if request_response.status_code == 200:

            request_response_json = request_response.json()

            # If the request did contain type information, add it to a list, else return an empty list.
            if len(request_response_json['data']['results']) == 1:

                logger.debug('The manager did return a type', extra={'type': request_response_json['data']['results'][0]})
                
                self.type_details = request_response_json['data']['results'][0]
                return self.type_details
                

            else:

                logger.error('The manager returned more than 1 type for a specific type ID', extra={'results': request_response_json['data']['results'][0]})
                
                return {}

        else:

            logger.error('The manager did not return 1 task', extra={'type': request_response_json['data']['results'][0]})
            
            return {}

    def update_task(self, task_id, task_status, task_output):
        """Will update a task status on the manager using the provided info

        Params:
            task_id: The ID of the task to update
            task_status: The exist status of the task, either [completed, failed]
            task_output: A dictionary to be passwd as the task output

        Returns:
            True if successful
            False if failed or error
        """
        self.task_id = task_id

        # Make sure have the latest task details stored
        self.get_task(self.task_id)

        if len(self.task_details) == 0:
            return False

        if task_status != None:
            self.task_details['status']['status'] = task_status
        if task_output != None:
            self.task_details['response'] = task_output

        self.request_host = self.host_base + f"/task"
        logger.debug('Sending PATCH request to the manager', extra={'request_host':  self.request_host, 'request_headers':  self.request_headers, 'json':self.task_details})

        request_response = requests.patch(self.request_host, headers=self.request_headers, json=self.task_details)

        logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code})

        if request_response.status_code == 200:

            request_response_json = request_response.json()

            logger.debug('Task updated successfully', extra={'request_response_json': request_response_json})
            return True

        else:
            logger.error('The manager did not respond with 200 when updating task', extra={'request_response_text': request_response.text, 'request_host':self.request_host})
            return False

class Task:
    def __init__(self, manager_address, manager_port, task_id):
        
        self.task_id = task_id
        self.manager_address = manager_address
        self.manager_port = manager_port

        # Query the manager for task and type deails
        query = Query(self.manager_address, self.manager_port, None)
        
        task_details = query.get_task(self.task_id)

        self.type_id = task_details['task']['type']
        self.paramaters = task_details['parameters']

        type_details = query.get_type(self.type_id)

        self.bin_name = type_details['bin']['name']
        self.bin_shasum = type_details['shasum']
        self.input_type = type_details['bin']['input']
        self.output_type = type_details['bin']['output']
        if 'exec' in type_details['bin']:
            self.bin_exec = type_details['bin']['exec']
        else:
            self.bin_exec = None

        # Set the Task status to accepted once we have everything
        self.status = "accepted"
        self.output = None
        query.update_task(self.task_id,self.status,self.output)

        # Needed for Task class to download bins
        self.host_base = f"http://{manager_address}:{manager_port}/api"
        self.request_headers = {"Accept": "application/json"}

    def __str__(self):
        return f"Task {self.task_id} executing {self.bin_name}"

    def __repr__(self):
        return f"{self.__class__.__name__}(task_id={self.task_id}, bin_name={self.bin_name}, bin_shasum={self.bin_shasum}, input_type={self.input_type}, paramaters={self.paramaters}, output_type={self.output_type})"

    def verify_bin(self):
        """Will check if a bin file exists on the syste and if the sha256 sum katches the one provided by the manager

        Params:
            type_bin_name: The name of the file to check
            type_bin_hash: The hash of the file, as reported by the manager to verify the file.

        Returns:
            * True if successfull
            * False if unsuccessfull
        """

        if os.path.isfile(f"types/{self.bin_name}"):
            logger.debug('Task type bin file exists on the system', extra={'type_bin_name': self.bin_name})

            existing_file_sha256_hash = hashlib.sha256()

            with open(f"types/{self.bin_name}","rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096),b""):
                    existing_file_sha256_hash.update(byte_block)

            if str(existing_file_sha256_hash.hexdigest()) == str(self.bin_shasum):
                logger.debug('The existing bin file is at the latest version', extra={'type_bin_name': self.bin_name, 'hash':existing_file_sha256_hash})
                return True
            else:
                logger.debug('The existing bin file is not latest version', extra={'type_bin_name': self.bin_name, 'file_hash':existing_file_sha256_hash, 'manager_hash':self.bin_shasum})
                return False
        else:
            logger.debug('Task type bin file does not exist on the system', extra={'type_bin_name': self.bin_name})
            return False

    def download_bin(self):
        """Will download the task bin file from the manager, and the check it using the provided sha256

        Params:
            type_id: The ID of thr task type to download
            task_bin_name: The name of the file to save as
            type_bin_hash: The hash of the file to verify against as proivided by the manager

        Retruns:
            * True if successful
            * False if unsuccessful
        """

        #Delete the file if it already exists
        if os.path.isfile(f"types/{self.bin_name}"):
            logger.debug('Task type bin file exists on the system, deleting', extra={'type_bin_name': self.bin_name})

        else:
            logger.debug('Task type bin file does not exist on the system, deleting', extra={'type_bin_name': self.bin_name})
            # Request task type bin from manager via task type download endpoint
            self.request_host = self.host_base + f"/type/download/{self.type_id}"
            self.request_headers = {"Accept": "*/*"}

            logger.debug('Sending GET query request to the manager', extra={'request_host': self.request_host, 'request_headers': self.request_headers})

            request_response = requests.get(self.request_host, headers=self.request_headers)
            logger.debug('Received response from the manager', extra={'body': request_response.text, 'status_code': request_response.status_code, 'headers':request_response.headers})

            # We might get a JSON response if something went wrong, so just check here, log and return false
            if request_response.headers.get('content-type') == 'application/json':

                request_response_json = request_response.json()
                logger.debug('Received JSON response from manager rather than a file when downloading type bin', extra={'type_id': self.type_id, 'json':request_response_json})
                return False

            else:
                if request_response.status_code == 200:
                    # Save the downaloded file to the types dir then check the hash matches
                    with open(f'types/{self.bin_name}', 'wb') as target_file:
                        target_file.write(request_response.content)

                    # Generate SHA256 sum for the bin file
                    logger.debug('Generating SHA256 hash for bin', extra={'bin':self.bin_name})

                    target_file_sha256_hash = hashlib.sha256()

                    with open(f"types/{self.bin_name}","rb") as f:
                        # Read and update hash string value in blocks of 4K
                        for byte_block in iter(lambda: f.read(4096),b""):
                            target_file_sha256_hash.update(byte_block)
                        
                    logger.debug('Generated SHA256 hash', extra={'hash':target_file_sha256_hash.hexdigest()})

                    if self.verify_bin():
                        logger.debug('Downloaded bin has been verified', extra={'file_hash':target_file_sha256_hash.hexdigest()})
                        return True
                    else:
                        logger.debug('Downloaded bin could not be verified. Download not successfull', extra={'file_hash':target_file_sha256_hash.hexdigest()})
                        return False
                elif request_response.status_code == 404:
                        logger.debug('Requesting a bin to download that did not exist, got 404', extra={'type_id':self.type_id})
                        return False
                else:
                        logger.debug('Error when dowloading bin', extra={'type_id':self.type_id})
                        return False

    def execute(self):
        """Will check that all required information is present, then execute the task.

        Params:

        Returns:
            True if successful, False if unsucsessful
        """     

        if (self.task_id != None) and \
            (self.bin_name != None) and \
            (self.task_id != None) and \
            (self.bin_shasum != None) and \
            (self.input_type != None) and \
            (self.paramaters != None) and \
            (self.status == "accepted"):

            logger.debug("All paramaters valid, executing task.", extra={'task_id':self.task_id, '__repr__':self.__repr__()})
        else:
            logger.error("Some paramateres were not valid, unable to execute task.", extra={'task_id':self.task_id, '__repr__':self.__repr__()})

            return False

        query = Query(self.manager_address, self.manager_port, None)

        if (self.bin_exec != None) and (self.bin_exec != ""):
            process_args = [f'{self.bin_exec} ']
        else:
            process_args = []

        process_args.append(os.path.join(os.path.abspath('types'), self.bin_name))

        self.download_bin()


        # Process input paramaters
        if self.input_type == "cli":
            logger.debug('The input type is CLI, checking paramaters dict', extra={'task_id':self.task_id,'paramaters':self.paramaters})

            # Prerper the task paramaters
            parsed_parameters = self.paramaters

            if isinstance(self.paramaters, dict):

                # Make sure paramaters is a single depth dictionary, error if not dict and change deppers keys to JSPON strings instead.
                for key in self.paramaters.keys():

                    if isinstance(self.paramaters[key], dict):

                        logger.debug('The provided dictionary has embedded keys, converting seccond depth value to JSON string', extra={'task_id':self.task_id, 'key':key,'paramaters':self.paramaters})
                        parsed_parameters[key] = json.dumps(self.paramaters[key])

                logger.debug('The paramaters dict as been compiled', extra={'task_id':self.task_id, 'parsed_parameters':parsed_parameters})
            
                # Build rest of subprocess args list
                for key in parsed_parameters:

                    process_args.append(str(key))
                    process_args.append(parsed_parameters[key])

                logger.debug('Process argument list is', extra={'task_id':self.task_id,'process_args':process_args})

                # Run basic subprocess
                query.update_task(self.task_id, "running", None)
                self.subprocess = subprocess.run(process_args, capture_output=True, text=True)

            else:
                logger.debug('The provided task paramaters is not a dictionary', extra={'task_id':self.task_id,'paramaters':self.paramaters})
                return False
        else:
            logger.error('Invalid input type', extra={'task_id':self.task_id, 'paramaters':self.paramaters})
            return False

        # Once subprocess has completed, parse any output and build a status dict

        self.process_output = {}
        self.process_output['meta'] = {}

        if self.subprocess.returncode == 0:
            self.process_output['meta']['successful'] = True
            self.process_output['meta']['retun_code'] = int(self.subprocess.returncode)
            self.status = "completed"
        else:
            self.process_output['meta']['successful'] = False
            self.process_output['meta']['retun_code'] = int(self.subprocess.returncode)
            self.status = "failed"

        self.process_output['stderr'] = str(self.subprocess.stderr)
        self.process_output['stdout'] = str(self.subprocess.stdout)

        if self.output_type == "stdout":
            self.process_output['output'] = str(self.subprocess.stdout)
        else:
            logger.error('Invalid output type when compiling resuts', extra={'task_id':self.task_id,'output_type':self.output_type})

        # Update the task's status on the manager with the process_output
        if query.update_task(self.task_id, self.status, json.dumps(self.process_output)):
            logger.debug('Task execution process completed successfully', extra={'task_id':self.task_id})
            return True
        else:
            logger.debug('Task execution process did not complete successfully', extra={'task_id':self.task_id})
            return False