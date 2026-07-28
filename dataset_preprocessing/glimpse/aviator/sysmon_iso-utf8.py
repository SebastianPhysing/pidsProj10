from lxml import etree

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

set_opcode   = set()
set_level    = set()
set_task     = set()
combination  = set()

with open("PIDSMaker/dataset_preprocessing/aviator/sysmon_audit_19_10_2023_0_45_42.94_DESKTOP-G3MEF77_apt29_scenario1.xml", "r", encoding="iso-8859-1", errors="ignore") as f:
    content = f.read()
content_utf8 = content.encode("utf-8", errors="ignore")
wrapped = "<Events>\n" + content + "\n</Events>"
with open("sysmon_fixed.xml", "w", encoding="utf-8") as f:
    f.write(wrapped)


for event, elem in etree.iterparse("sysmon_fixed.xml", events=("end",), tag=f"{{{NS}}}Event"):
    ri = elem.find(f"{{{NS}}}RenderingInfo")
    if ri is not None:
        opcode = ri.findtext(f"{{{NS}}}Opcode")
        level  = ri.findtext(f"{{{NS}}}Level")
        task   = ri.findtext(f"{{{NS}}}Task")

        set_opcode.add(opcode)
        set_level.add(level)
        set_task.add(task)
        combination.add((opcode, level, task))

    elem.clear()

none_last = lambda x: (x is None, x or "")
print("\nAll combinations (opcode, level, task)\n")
print(combination)
print("\nOpcode\n")
print(set_opcode)

print("\nLevel\n")
print(set_level)

print("\nTask\n")
print(set_task)




