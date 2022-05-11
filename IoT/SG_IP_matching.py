# this function is to evaluate if IPs are from SG
import ipaddress
import pandas as pd
from datetime import datetime

def match_SG_IP(df, output_filename):
    # load PoC-monitored-APIxlsx file
    SG_IP = pd.read_excel("PoC-monitored-APxlsx.xlsx")

    is_SG_IP = []
    for i in df['SrcIP']:
        for ip in range(0, len(SG_IP['Monitored Subnets'])-2):
            if ipaddress.ip_address(i) in ipaddress.ip_network(SG_IP['Monitored Subnets'][ip]):
                val = SG_IP['As Name'][ip]
                break
            else:
                val = 'No'
        is_SG_IP.append(val)
    df['As Name'] = is_SG_IP
    df.to_csv("check_IP_address_" + output_filename + str(datetime.now().strftime('%Y_%m_%d_%H_%M_%S')) + ".csv", index=False)
    return df