from Evtx.Evtx import Evtx

def evtx_to_xml(evtx_path, xml_path):
    with Evtx(evtx_path) as log, open(xml_path, "w", encoding="utf-8") as out:
        out.write("<Events>\n")
        for record in log.records():
            try:
                out.write(record.xml())
                out.write("\n")
            except Exception as e:
                print(f"Skipped record: {e}")
        out.write("</Events>\n")

evtx_to_xml("PIDSMaker/dataset_preprocessing/cylab/1/Evtx_Logs/System.evtx", "PIDSMaker/dataset_preprocessing/cylab/1/Evtx_Logs/system.xml")
