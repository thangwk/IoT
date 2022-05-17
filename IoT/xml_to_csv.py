import os
import pandas as pd
import xml.etree.ElementTree as ET

def xml_to_csv(directory, output_filename):
    file_list = os.listdir(directory)
    cols = ['EventType', 'CreateTime', 'AlertID', 'OrgID', 'Trigger', 'Duration', 'EventTime', 'EventID', 'SrcIP',
            'SrcCC', 'TotalPacketCount', 'DisplayPacketCount', 'Type', 'PacketTime', 'DstIP', 'DstCC', 'DstPort',
            'SrcPort', 'Protocol', 'Flag', 'DarknetType']

    for file in file_list:
        rows = []
        tree = ET.parse(directory + "\\" + file)
        root = tree.getroot()
        new_dict = {}

        for text in root.iter():
            if text.text and text.text.strip():
                key = str(text.tag)
                value = text.text
                new_dict[key] = value
        for child in root:
            new = new_dict.copy()
            if child.tag == 'Header':
                pass
            elif child.tag == 'DaedalusAlertHeader':
                new['EventType'] = 'DaedalusAlert'
            else:
                keys_list = list(child.attrib)

                for i in keys_list:
                    val = child.attrib[i]
                    new[i] = val
                for j in range(len(child)):
                    keys = list(child[j].attrib)

                    for k in keys:
                        new[k] = child[j].attrib[k]
                    # doing a copy as appending to a list will overwrite the existing dictionary
                    dictionary_copy = new.copy()
                    rows.append(dictionary_copy)
        df = pd.DataFrame(rows, columns=cols)

        # writing dataframe to csv

        df.to_csv(output_filename, mode='a', index=False, header=not os.path.exists(output_filename))
        rows = []
        output = pd.read_csv(output_filename)
        return output