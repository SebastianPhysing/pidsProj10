
import pandas as pd

csv_path = "PIDSMaker/dataset_preprocessing/dedale/D2_2024-12-24_output_orange_dmz.pcap_Flow_labeled.csv"

with open(csv_path, newline="", encoding="utf-8") as f:
    
    table = pd.read_csv(csv_path)
    print(table.columns)

