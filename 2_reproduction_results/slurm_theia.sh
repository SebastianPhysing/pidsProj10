#!/bin/bash
#SBATCH --job-name=pids_repro_THEIA-E5
#SBATCH --partition=standard
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --mem=128G
#SBATCH --cpus-per-task=16
#SBATCH --gres=gpu:L40:1,tmp:250G
#SBATCH --time=24:00:00
#SBATCH --output=slurm-%j.out

set -u

# Tmp storage to save individiual results of each step, which is used to resume from succedding steps
# we save them in the /tmp - space, since the home space is limited (187GB), we discard all results expect the evaluation step, which will the be saved in $home/PIDSMaker/artifacts/THEIA_E5_{SLURM_JOB_ID}
SCRATCH="${TMPDIR:-/tmp}/pids_${SLURM_JOB_ID}"
ARTIFACTS="$SCRATCH/artifacts"
mkdir -p "$ARTIFACTS"
# after finishing the $SCRATCH will be removed
trap 'echo "Cleanup $SCRATCH"; rm -rf "$SCRATCH"' EXIT

# Destination folder for evaluation step
RESULTS="$HOME/PIDSMaker/artifacts/THEIA_E5_${SLURM_JOB_ID}"
mkdir -p "$RESULTS"




export WANDB_API_KEY=<YOUR_WANDB_API_KEY>
export PYTHONUNBUFFERED=1


cd ~/PIDSMaker/scripts/apptainer/
make up

source ~/python/venvs/pids/bin/activate
wandb login

PROJECT="pids_repro_THEIA-E5"
cd ~/PIDSMaker
export PYTHONPATH=$PWD:$PYTHONPATH
export APPTAINERENV_CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0}

# After each run, save a
save_eval () {
    local system="$1"
    if [ -d "$ARTIFACTS/evaluation" ]; then
        rsync -a "$ARTIFACTS/evaluation/" "$RESULTS/evaluation/"
        echo "[$system] Successful transfered evaluation to home dictionary: -> $RESULTS/evaluation/"
    else
        echo "[$system] WARNUNG: no evaluation dictionary found!"
    
    
}

# Tuned hyperparameters: https://ubc-provenance.github.io/PIDSMaker/tuned_systems/

# --- VELOX -----------------------------------------------------------------
echo "########## VELOX $(date) ##########"
python -u pidsmaker/main.py velox THEIA_E5 \
  --artifact_dir "$ARTIFACTS/" --database_host localhost \
  --training.encoder.dropout=0.3 --training.lr=0.0001 \
  --training.node_hid_dim=128 --training.node_out_dim=128 \
  --training.num_epochs=12 --featurization.emb_dim=128 \
  --construction.time_window_size=15.0 \
  --experiment=run_n_times --wandb \
  --project="$PROJECT" --exp="velox_dataset_5x" \
  > "$RESULTS/velox.log" 2>&1 \
  || echo "!!! FAILED VELOX THEIA_E5"
save_eval velox

# --- ORTHRUS ---------------------------------------------------------------
echo "########## ORTHRUS $(date) ##########"
python -u pidsmaker/main.py orthrus_non_snooped THEIA_E5 \
  --artifact_dir "$ARTIFACTS/" --database_host localhost \
  --training.encoder.dropout=0.3 --training.lr=0.001 \
  --training.node_hid_dim=256 --training.node_out_dim=256 \
  --training.num_epochs=12 --featurization.emb_dim=64 \
  --experiment=run_n_times --wandb \
  --project="$PROJECT" --exp="orthrus_non_snooped_dataset_5x" \
  > "$RESULTS/orthrus.log" 2>&1 \
  || echo "!!! FAILED ORTHRUS THEIA_E5"
save_eval orthrus

# --- NODLINK ---------------------------------------------------------------
echo "########## NODLINK $(date) ##########"
python -u pidsmaker/main.py nodlink THEIA_E5 \
  --artifact_dir "$ARTIFACTS/" --database_host localhost \
  --training.encoder.dropout=0.3 --training.lr=0.001 \
  --training.node_hid_dim=320 --training.node_out_dim=320 \
  --training.num_epochs=12 --featurization.emb_dim=128 \
  --featurization.epochs=20 --construction.time_window_size=15.0 \
  --transformation.used_methods="none" \
  --experiment=run_n_times --wandb \
  --project="$PROJECT" --exp="nodlink_dataset_5x" \
  > "$RESULTS/nodlink.log" 2>&1 \
  || echo "!!! FAILED NODLINK THEIA_E5"
save_eval nodlink

# ---------------------------------------------------------------------------
echo "-------Finished-------"
du -sh "$RESULTS" 2>/dev/null
/usr/local/bin/getquota.sh

cd ~/PIDSMaker/scripts/apptainer/
make down