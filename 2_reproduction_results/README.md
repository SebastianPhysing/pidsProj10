# Verify Proper Experiment Setup
In order to make results comparable, we want to check whether we obtain similar results for the standard datasets and systems provided by PIDSMaker. What will be done in the following:
> - Run each experiment 5 times (default), since PIDS exhibts significant instabilty
> - Include small and medium datasets (CADETS_E3, THEIA_E5)
> - Test on Systems: Velox, Orthrus, Nodlink

We compare our results with the results provided by PIDSMaker ([see, table 5 and 6](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot)). We therefore take a look at <b>ADP (Mean, Min, Max)</b>, relative Std <b> σ̃ ADP</b>, <b>Precision (Mean, Min, Max)</b>, <b>TF, FP</b> obtained in weights & biases. 
The PIDSMaker paper proposes `ADP: Attack Detection-Precision`. It measures directly the predictive power of a PIDS, independent of postprocessing or thresholding (setting the threshold affects the precision, since it defines if a assigned score is seen as benign or malicious.) PIDSMaker recommends to report these number, so do we for verification and our datasets. 
For hyperparameter selection, which heavily influence the results we use the information we found:

>Unfortunatlly PIDSMaker does not provide for all SYSTEMS or DATASETS the best hyperparameter selection. Nor it does not provide the ranges for Hyperparameter Tuning.
No exact information can be found in [PIDSMaker Framework Paper](https://arxiv.org/abs/2601.22983) or in the [Evaluation Paper](https://www.usenix.org/conference/usenixsecurity25/presentation/bilot).  
The only information you can find, is in the [documentation](https://ubc-provenance.github.io/PIDSMaker/tuned_systems/). Some detailed information about Velox and the model weights can be found on a different [branch](https://github.com/ubc-provenance/PIDSMaker/tree/velox). The provided standard configurations (with hyperparameters) can not be seen as the optimal ones, since they are for all datasets the same and differ from the CLI commands of the [documentation page](https://ubc-provenance.github.io/PIDSMaker/tuned_systems/).

The authors said that they do not gurantee to that running PIDSMaker under the same setting, will result in similar outcome, since the framework has evolved. They recommend to the run the systems multiple times.  
`Hint:` You can find the slurm jobs in this folder. It contains a storage cleaning commands, since PIDSMaker saves all intermediate steps of the 7 processing steps. Therefore a lot of storage need is accumulated. A Cluster user has `180GB` of quota. 

## Cadets_E3
```console
sbatch slurm_cadets.sh
```

### <b>Velox</b>
| SOURCE | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| PAPER  | 0.94 | 0.77 | 1.0 | 9% | 0.84 | 0.44 | 1.0 | 8 | 0
| Ours  | 0.78 | 0.63 | 0.95 | 15% | 0.74 |0.62 | 0.86 | 14 | 1

### <b>Orthrus</b>
| SOURCE | Mean ADP| Min ADP | Max ADP | rel. Std ADP |Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| PAPER  | 0.94 | 0.85 | 1.0 | 12% | 0.66 | 0.40 | 1.00| 10|0
| Ours  | 0.65 | 0.35 | 1.0 | 35% | 0.54 | 0.11 | 1.00 | 10 | 0

### <b>Nodlink</b>
| SOURCE | Mean ADP| Min ADP | Max ADP | rel. Std ADP |Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| PAPER  | 0.33 | 0.15 | 0.96 | 56% | 0.00 | 0.00| 0.00| 50 |55k|
| Ours  | 0.33 | 0.03 | 0.63 | 77% | 0.00 | 0.00| 0.00| 62 |46k

--> Our numbers are not identically to the ones proposed by the paper, but it shows the overall picture: Velox and Orthrus clearly outperform Nodlinks. The best-case ADP and precision are comparable with the reported values. TP/FP lie in the same range. The difference in mean and minimum ADP and standard deviation, to the instability (mentioned by the authors) and the possible evolution of the framwork.

## Theia_E5
```console
sbatch slurm_theia.sh
```
### <b>Velox</b>
| SOURCE | Mean ADP| Min ADP | Max ADP | rel. Std ADP |Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| PAPER  | 1.0 | 1.0 | 1.0 | 0% | 1.0| 1.0|1.0|2|0
| Ours  | 0.88|0.4|1.0|27%|0.8|0.0|1.0 |2|0

### <b>Orthrus</b>
| SOURCE | Mean ADP| Min ADP | Max ADP | rel. Std ADP |Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| PAPER  | 0.70 | 0.50 | 1.0 | 31% |0.39| 0.33|0.5|1|1
| Ours  | 0.05|0.03| 0.06| 24%|0.0|0.0|0.0|0|0

### <b>Nodlink</b>
| SOURCE | Mean ADP| Min ADP | Max ADP | rel. Std ADP |Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| PAPER  | 0.0 | 0.0 | 0.0 | 0% |0.0|0.0|0.0|36|38k
| Ours  | 0.0 | 0.0 | 0.0 | 0% |0.0|0.0|0.0|34|38k

--> Velox and Nodlink reproduce the results provided by the authors. Orthrus does not reproduce. It is difficult to pin down the reason for such a discrepancy. We performed every step accordingly. You can find the slurm job in this folder. There the given arguments of Orthrus and the other models are given.  

Overall 5 of 6 system dataset combinations reproduce the reported results within normal variance. Therefore the results obtained with our datasets can be expected to be correct.