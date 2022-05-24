# this is the main program

#import load_data
import IP_address_filter
import SG_IP_matching
import xml_to_csv
import virusTotal_api
import Opensearch_API
import pandas as pd
from datetime import datetime
import time
import os
from tqdm import tqdm

def main():
    #set folder that you want to save the xml files to
    #folder = directory

    #step 1: load xml files into folder from outlook email
    #load_data.load_data(folder)

    # Optional. Change to directory that you want to save the results at
    # os.chdir()

    # step 2: convert xml files to and aggregate all into a single csv
    #df = xml_to_csv.xml_to_csv(folder, output.csv)

    # step 3: do groupby to get highest packets and highest alerts based on IP
  #  df = pd.read_csv(r"D:\Data\alerts.csv")
  #  highest_packet, highest_alert = IP_address_filter.IP_address_grouping(df)
  #  print("Step 3 done")

    # Optional. Change to directory that you want to save the results at
    # os.chdir()

    # step 4: check if IP belongs to SG
    #SG_highest_packet = SG_IP_matching.match_SG_IP(highest_packet, "SG_highest_packet_matched")
  #  SG_highest_alert = SG_IP_matching.match_SG_IP(highest_alert, "SG_highest_alert_matched")
  #  print('Step 4 done')

    SG_highest_alert = pd.read_csv("D:\Projects\IoT\data\check_IP_address_SG_highest_alert_matched_2022_05_23_17_36_23.csv")
    # # step 5: check if IP address is in Virustotal
    # # create columns to store response from API

    SG_highest_alert.reindex(columns=SG_highest_alert.columns.tolist() + ["Community_score", "harmless", "malicious",
                                                                          "suspicious", "undetected", "timeout",
                                                                          "Engines"])

    ip_address = SG_highest_alert['SrcIP'].unique()
    output_filename = "D:\Projects\IoT\data\VT_matched" + "_" + str(datetime.now().strftime('%Y_%m_%d_%H_%M_%S')) + ".csv"
    for ip in tqdm(ip_address, desc="Step 5: virus total checks"):
        response = virusTotal_api.api_call_virustotal(ip)
        stats_output, new_list, harmless, malicious, suspicious, undetected, timeout = virusTotal_api.read_response(response)
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['Community_score']] = stats_output
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['harmless']] = harmless
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['malicious']] = malicious
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['suspicious']] = suspicious
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['undetected']] = undetected
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['timeout']] = timeout
        SG_highest_alert.loc[SG_highest_alert['SrcIP'] == ip, ['Engines']] = (','.join(new_list))

        time.sleep(30)  # delay 12sec as calls to virustotal api is 2 per min

    SG_highest_alert.to_csv(output_filename, index=False)

    print('Step 5 done')

    # step 6: check if IP address is in Opensearch
    os.chdir(r"D:\Projects\IoT\data")
    SG_highest_alert = pd.read_csv("D:\Projects\IoT\data\VT_matched.csv")
    OS_search = SG_highest_alert[SG_highest_alert['Community_score']==0]
    print(len(OS_search['SrcIP']))
    df_os = pd.DataFrame(columns=['Source IP','Source Port','loggedin','Dest IP','Dest Port','Source Country','Commands','urls','hashes','startTime','stopTime'])

    #pbar = tqdm(total=len(OS_search['SrcIP']))
    for j in tqdm(OS_search['SrcIP'], desc = "Step 6: Open Search API checks"):
        data = Opensearch_API.opensearch_request(start_date = "2022-02-01T16:00:00.000Z", end_date = "2022-02-28T15:59:59.999Z", ip = j)
        df_os = pd.concat([df_os,data])
        #pbar.update(1)
    #pbar.close()
    df_os.to_csv("opensearch_matched" + "_" + str(datetime.now().strftime('%Y_%m_%d_%H_%M_%S')) + ".csv", index=False)
    print('Step 6 done')

if __name__ == "__main__":
    main()