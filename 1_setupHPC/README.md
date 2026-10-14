# Running PIDSMaker on HPC Cluster JMU Julia2 
See <b>Automatic Download & Setup</b> for script-based setup.
## Create HPC Login Account
This can take a few days, since it has to be confirmed by a human.
## Connect To Server
- start VPN connection via Cisco Secure Connect
- open terminal (STRG + Alt + T) and connect using your s-id via:
```console
ssh sxxxxxx@julia2.hpc.uni-wuerzburg.de
```

- use your JMU (Microsoft) Login Password for authentification
## Get PIDSMaker On Server
You land in the ```$HOME```dictionary and in the "login node" (as a user, you can only use up to 16GB RAM and 8 cores), it is not intended for running your experiments nor for testing whether your script works well. It is purely for setting up your work enviroment. This is what will be done in the following.  
  
Clone PIDSMaker (e.g. directly in your ```$HOME```(```~```)):
```console
git clone https://github.com/ubc-provenance/PIDSMaker.git
```

## Download Datasets & Create Database Apptainer

In the official documentation it is mentioned to easily set up with  ```make full-setup```. It is not mentioned to download the datasets manually, but it is important. No downloading takes place in full-setup.
As a first step we create the apptainer by running:
```console
cd ~/PIDSMaker/scripts/apptainer
make full-setup
```
The apptainer automatically started. If not type ```make up```.  
Afterwards we use the script ```download_datasets``` mentioned in the docker installation guide. It may be neccessary to run ```chmod +x ~/PIDSMaker/download_datasets.sh```. You can define the datasets you would like to have. As a next step we move the data to the apptainer/data folder. To do so, run:
```console
cd ~/PIDSMaker/scripts/apptainer/
mv ~/PIDSMaker/data/* ./data
```
Now we load the data dumps in the recently created databases. This can take quite some time.
```console
apptainer shell instance://postgres_instance
./load_dumps.sh
``` 
Afterwards you can leave the apptainer: run ```exit```
Now the databases are filled.


Make sure to ```make down``` since you don't want to keep the apptainer 'pidsmaker' running on the login node.
### Check succeed of apptainer database
If you want to verify, that the tables are really filled with data do:
1. Start the apptainer: ```make up```
2. Go into the apptainer: ```apptainer shell instance://postgres_instance```
3. Log into the Postgres Database: ```psql -U postgres```
4. See a list of datasets saved in psql: ```\l```
5. Log into a concret database, e.g. cadets_e3: ```\c cadets_e3 ```
6. Show tables: ```\dt```
7. Quit and exit apptainer and shut it down: 
```console
\q
exit
make down
```

## Create Python Enviroment
Unfortunatlly the use of conda is not possible on the HPC Cluster due to licensing. Therefore <b>Pyenv</b> is used to use a specific python version: 
### Install PYENV 
Create dictonaries:
```console
mkdir -p ~/python/{pyenv,venvs}
``` 
Clone Pyenv repository:
```console
git clone https://github.com/pyenv/pyenv.git ~/python/pyenv
```
Make it avaible in every shell by adding the following to your ```~/.bashrc``` file:  

```console 
export PYENV_ROOT="$HOME/python/pyenv" 
[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"  
eval "$(pyenv init - bash)"   
```  
Reload the shell afterwards (```source ~/.bashrc```) so the changes take effect.  

Now install the required Python version (can be found in ```/scripts/apptainer/enviroment.yaml```) and set it as the global default:

```console
pyenv install 3.9.23
pyenv global 3.9.23
pip install --upgrade pip
```
Next, create a virtual environment based on this Python version and install the project dependencies from ```requirements.txt```:

```console
cd ~/python/venvs
python -m venv pids
source pids/bin/activate

```
Create requirements file and paste the content from requirements.txt:
```console
cd pids
nano requirements.txt
```
Install the dependencies with the help of pip:
```console
pip install -r requirements.txt 
```
The installation path of the venv is important for creating a sbatch file and run the job. Therefore, make sure to remember it.

## Automatic Download & Setup
Downloading and creating the databases can become a quite time consuming task. It is not wise to perform each step in the CLI one after another and tie the login node for such a large task. Therefore you can create a slurm job and delegate the task to a dedicated CPU node. All steps described above, are performed in ```complete_setup.sh```.  
Specify the datasets, you want to download by changing the line:
```console
./download_datasets.sh [all,cadets_e3,optc_h201,clearscope_e5, ...] YOUR_ACCESS_TOKEN
```
Make also sure to generate a Access Token and set it in the file, [see](https://ubc-provenance.github.io/PIDSMaker/ten-minute-install/#option-2-from-cli).  
 You can lay back and don't need to wait that every indiviudal task has finished.

## Create Test Job
Until now we have everything set up in the login node . Now we check whether everything works as intended.  
We do that on the 'test' partion (only one node, time limit: 1 hour). For running experiments, other partitions can be specified (for gpu partitions: time limit 1 day --> make sure to save your job and resume if necessary). You can see all partitions and the according number of nodes (a node represents a physical / virtual system) typing:
```console
sinfo
```  
If you want to run PIDSMaker, you can create a SLURM Jobfile. For example like ```test_velox.sh```. At the top the specification of a node you want, is defined. Afterwards every command is executed on that node.  
Make sure to specify your Weights&Bias API Key, if you want to make use of it. If not, remove the line and the ```--wandb``` argument for the python script.  
In order to submit your job, run
```console
sbatch test_velox.sh
```

### Useful commands to take a look at
- Lists all currently queued and running jobs.
```console
squeue
```
- Prints the whole log file of the job once (snapshot) (print statements your script produced)
```console
cat slurm-<id>.job
```
- Follows the log file live and keeps printing new lines as they are written, not just a snapshot.
```console
tail -f slurm-<id>.job
```
- Opens an interactive shell on the node of an already running job (--overlap lets it share the existing allocation), so you can inspect the environment while the job runs.
```console
srun --pty --overlap --jobid <your_job_id> /bin/bash
```
- Open htop on the job's node to inspect CPU and RAM usage interactively
```console
srun --jobid=<your_job_id> --pty htop
```
- Shows the GPU status on the job's node once (snapshot)
```console
srun --jobid=<your_job_id> --pty nvidia-smi
```
- Refreshes nvidia-smi every second
```console
srun --jobid=<your_job_id> --pty watch -n 1 nvidia-smi
```
- Show accounting info for a (also already finished) job. Run ```sacct --helpformat``` to see all available fields
```console
sacct -j <your_job_id> --format=JobID,State,MaxRSS,Elapsed
```








