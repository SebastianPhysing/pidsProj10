# Verify Proper Experiment Setup
In order to make results comparable, we want to check whether we obtain similar results for the standard datasets and systems provided by PIDSMaker. What will be done in the following:
> - Run each experiment 5 times (default), since PIDS exhibts significant instabilty
> - Include small and medium datasets (OPTC_H201, CADETS_E3, THEIA_E5)
> - Test on Systems: Velox, Orthrus, Nodlink

We compare our results with the results provided by PIDSMaker ([see, table 5 and 6](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot)). We therefore take a look at <b>ADP (Mean, Min, Max)</b>, relative Std <b> σ̃ ADP</b>, <b>Precision (Mean, Min, Max)</b>, <b>TF, FP</b> obtained in weights & biases.  
For hyperparameter selection, which heavily influence the results we use the information we found:

>Unfortunatlly PIDSMaker does not provide for all SYSTEMS or DATASETS the best hyperparameter selection. Nor it does not provide the ranges for Hyperparameter Tuning.
No exact information can be found in [PIDSMaker Framework Paper](https://arxiv.org/abs/2601.22983) or in the [Evaluation Paper](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot).  
The only information you can find, is in the [documentation](https://ubc-provenance.github.io/PIDSMaker/tuned_systems/). Some detailed information about Velox and the model weights can be found on a different [branch](https://github.com/ubc-provenance/PIDSMaker/tree/velox). The provided standard configurations (with hyperparameters) can not be seen as the optimal ones, since they are for all datasets the same and differ from the CLI commands of the [documentation page](https://ubc-provenance.github.io/PIDSMaker/tuned_systems/).

The authors said that they do not gurantee to that running PIDSMaker under the same setting, will result in similar outcome, since the framework has evolved. They recommend to the run the systems multiple times. 

## Optc_h201
```console
sbatch slurm_optc.sh
```
## Cadets_E3
```console
sbatch slurm_cadets.sh
```
## Theia_E5
```console
sbatch slurm_theia.sh
```
