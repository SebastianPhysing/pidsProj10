#!/bin/bash
#SBATCH -J PIDS
#SBATCH -c 16
#SBATCH -p test
#SBATCH --gres=gpu:1
#SBATCH --mem=128G
#SBATCH --mail-type=ALL
#SBATCH --mail-user=<your-email-address>


export APPTAINERENV_CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES}
echo ${CUDA_VISIBLE_DEVICES}

export WANDB_API_KEY=<YOUR-W&B-KEY-HERE>

# start apptainer database
cd ~/PIDSMaker/scripts/apptainer/
make up

# run pidsmaker with the help of venv
cd ~/python/venvs

# activate venv
source pids/bin/activate

# to export results to weights & biases
wandb login

cd ~/PIDSMaker

# in order to find pidsmaker as package, otherwise: no module found 'pidsmaker'
export PYTHONPATH=$PWD:$PYTHONPATH

python pidsmaker/main.py velox CADETS_E3 --artifact_dir ./artifacts/ --database_host localhost --wandb

# shut down apptainer database
cd ~/PIDSMaker/scripts/apptainer/

make down
