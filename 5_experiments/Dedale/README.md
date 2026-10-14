
# Evaluation of the Performances of PIDSMaker models on Dedale
If you take a look at Theias or Cadets ground truth data, there are a small number of entries in the csv files. Which means it uses a rather strict understanding of malicious.  
On the other hand the malicious events provided by dedale are much more. This arises the question whether all events and their according nodes/edges are relevant. Generating all nodes of the events, results in many File nodes, regarding pip installtion and only few subject nodes. We evaluated two cases for both clients: only subject nodes and all node types.  
To account for instability every method is performed 5 times.
## Client1 - infected by Client2
```console
sbatch slurm_client1.sh
```

### <b>Velox</b>

| Node types | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| all  | 0.99 | 0.99 | 1.0 | 0.0% | 0.51 | 0.2 | 1.0 | 3 | 0
| only subjects  | 1.0 | 1.0 | 1.0 | 0.0% | 0.39 |0.22 | 0.66 | 2 | 1

### <b>Orthrus</b>

| Node types | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| all| 0.34 | 0.27 | 0.39 | 12.2% | 0.06 |0.04 | 0.08 | 2 | 1
| only subjects  | 0.27 | 0.13 | 0.33 | 29.6% | 0.05 | 0.05 | 0.07 | 1 | 14


### <b>Nodlink</b>

| Node types | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| all  | 0.31 | 0.1 | 1.0 | 111.4% | 0.00 | 0.00 | 0.00 | 57 | 49k
| only subjects  | 0.37 | 0.04 | 1.0 | 94.1% |  0.00 | 0.00 | 0.00 | 14 | 50k

## Client2 - Email infection
```console
sbatch slurm_client2.sh
```

### <b>Velox</b>

| Node types | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| all  | 0.94 | 0.73 | 0.99 | 11.5% | 0.74 | 0.72 | 0.8 | 16 | 3
| only subjects  | 0.91 | 0.55 | 1.0 | 20.0% | 0.59 |0.55 | 0.70 | 14 | 5

### <b>Orthrus</b>

| Node types | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| all| 0.99 | 0.99 | 1.0 | 0.22% | 0.60 |0.33 | 1.00 | 1 | 16
| only subjects  | 1.0 | 1.0 | 1.0 | 0.0% | 0.12 | 0.11 | 0.14 | 1 | 6


### <b>Nodlink</b>

| Node types | Mean ADP| Min ADP | Max ADP | rel. Std ADP | Mean Prescision | Min Precision | Max Precision | Best TP | Best FP
|:-------------- |:----:|:---------:|:----:|:----------:|:----------:|:----------:|:----------:|:----------:|:----------:|
| all  | 0.83 | 0.17 | 1.0 | 40.0% | 0.00 | 0.00 | 0.00 | 40 | 23k
| only subjects  | 0.73 | 0.17 | 1.0 | 46.8% |  0.00 | 0.00 | 0.00 | 5 | 23k

## Discussion
The PIDSMaker paper proposed Velox a small PIDS outperforming the state of the art popular methods. The strong and stable performance of Veloc is according to our dataset dedale and our parser. It is the best performing model over all cases. Also Nodlink has a similar behaviour. Its near-zero precision with tens of thousand of false positives is identically to the Darpa Datasets which is due its low threshold. But it has also predictive power, as can be seen in the ADP score.

You have to keep in mind that Dedale only has one attack scenario, the malicious understanding of dedale is broader and the benign activity is scripted (PIDSMaker paper mentions that this improves performance).  

What is interessting, the large difference between Orthrus performances on client1 and client2. This may come from the attack scenario: client2 sends malware via PrintNightmare to client1. On client1 (with poorer performance) this might be seen as a normal/legitimate system process. 


Regarding the node types, the ADP barely differs between the two settings, but precision is consistently higher when all node types are included (e.g. VELOX on Client2: 0.74 vs. 0.59, ORTHRUS on Client2: 0.40 vs. 0.12). This is expected: including the many file nodes enlarges the set of malicious labels, so a flagged node is more likely to count as a true positive. The subject-only setting is therefore the stricter one and closer to the DARPA ground truth..