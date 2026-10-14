#!/bin/bash
#SBATCH --job-name=pids_dedale_winlog_client1
#SBATCH --partition=standard
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=128G
#SBATCH --gres=gpu:L40:1
#SBATCH --time=1-00:00:00
#SBATCH -o slurm-%j_client1.out

export APPTAINERENV_CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES}
echo ${CUDA_VISIBLE_DEVICES}

export WANDB_API_KEY=

cd ~/PIDSMaker/scripts/apptainer/
make up
sleep 30

export PYENV_ROOT="$HOME/python/pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init - bash)"
source ~/python/venvs/pids/bin/activate

wandb login

PROJECT="pids_dedale_CLIENT1"
cd ~/PIDSMaker
export PYTHONPATH=$PWD:$PYTHONPATH

python pidsmaker/main.py velox CLIENT1 --artifact_dir ./artifacts/ --database_host localhost --experiment=run_n_times --wandb --exp="velox_client1_5x" \
  || echo "!!! FAILED VELOX CLIENT1"

python pidsmaker/main.py orthrus_non_snooped CLIENT1 --artifact_dir ./artifacts/ --database_host localhost --experiment=run_n_times --wandb --exp="orthrus_client1_5x" \
  || echo "!!! FAILED ORTHRUS CLIENT1"

python pidsmaker/main.py nodlink CLIENT1 --artifact_dir ./artifacts/ --database_host localhost --experiment=run_n_times --wandb --exp="nodlink_client1_5x" \
  || echo "!!! FAILED NODLINK CLIENT1"

cd ~/PIDSMaker/scripts/apptainer/
make down