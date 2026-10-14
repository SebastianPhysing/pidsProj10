#!/bin/bash
#SBATCH --job-name=pids_repro_CADETS-E3
#SBATCH --partition=standard             
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=128G
#SBATCH --gres=gpu:L40:1                    
                                         


export WANDB_API_KEY=<YOUR_WANDB_API_KEY>
# start apptainer database
cd ~/PIDSMaker/scripts/apptainer/
make up

# run pidsmaker with the help of venv
cd ~/python/venvs

# activate venv
source pids/bin/activate


wandb login

PROJECT="pids_repro_CADETS-E3"       
cd ~/PIDSMaker

export PYTHONPATH=$PWD:$PYTHONPATH

# Used tuned hyperparameters from docs: https://ubc-provenance.github.io/PIDSMaker/tuned_systems/
# runs n times (default: 5)
# VELOX
python pidsmaker/main.py velox CADETS_E3 --artifact_dir ./artifacts/ --database_host localhost \
  --training.encoder.dropout=0.3 --training.lr=0.0001 \
  --training.node_hid_dim=256 --training.node_out_dim=256 \
  --training.num_epochs=12 --featurization.emb_dim=256 \
  --experiment=run_n_times --wandb \
  --project="$PROJECT" --exp="velox_dataset_5x" \
  || echo "!!! FAILED VELOX CADETS_E3"
  
  

# ORTHRUS
python pidsmaker/main.py orthrus_non_snooped CADETS_E3 --artifact_dir ./artifacts/ --database_host localhost \
  --training.encoder.dropout=0.3 --training.lr=0.001 \
  --training.node_hid_dim=256 --training.node_out_dim=256 \
  --training.num_epochs=12 --featurization.emb_dim=256 \
  --experiment=run_n_times --wandb \
  --project="$PROJECT" --exp="orthrus_non_snooped_dataset_5x" \
  || echo "!!! FAILED ORTHRUS CADETS_E3"

# NODLINK
python pidsmaker/main.py nodlink CADETS_E3 \
  --training.encoder.dropout=0.3 --training.lr=0.001 --artifact_dir ./artifacts/ --database_host localhost \
  --training.node_hid_dim=320 --training.node_out_dim=320 \
  --training.num_epochs=12 --featurization.emb_dim=128 \
  --featurization.epochs=20 --construction.time_window_size=15.0 \
  --transformation.used_methods="none" \
  --experiment=run_n_times --wandb \
  --project="$PROJECT" --exp="nodlink_dataset_5x" \
  || echo "!!! FAILED NODLINK CADETS_E3"

# shut down apptainer database
cd ~/PIDSMaker/scripts/apptainer/

make down