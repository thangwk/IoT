# this function is to evaluate if IPs are from SG
import ipaddress
import pandas as pd
import shodan
from datetime import datetime

import config
SHODAN_API_KEY = config.shodan_api_key

api = shodan.Shodan(SHODAN_API_KEY)
def match_SG_IP(df, output_filename):
    # load PoC-monitored-APIxlsx file
    SG_IP = pd.read_excel(r"D:\Data\DarkNet\PoC-monitored-APxlsx.xlsx")

    is_SG_IP_BGP = []
    is_SG_IP_Shodan = []
    for i in df['SrcIP']:
        # shodan checks
        try:
            host = api.host(i)
            is_SG_IP_Shodan.append(host['country_code'])
        except:
            is_SG_IP_Shodan.append('No')
        for ip in range(0, len(SG_IP['Monitored Subnets'])-2):
            if ipaddress.ip_address(i) in ipaddress.ip_network(SG_IP['Monitored Subnets'][ip]):
                val = SG_IP['As Name'][ip]
                break
            else:
                val = 'No'
        is_SG_IP_BGP.append(val)
    df['As Name BGP'] = is_SG_IP_BGP
    df['Shodan Check'] = is_SG_IP_Shodan
    df_ = df[(df['As Name BGP']!="No") | (df['Shodan Check']=='SG')]
    df_.to_csv("check_IP_address_" + output_filename + "_" + str(datetime.now().strftime('%Y_%m_%d_%H_%M_%S')) + ".csv", index=False)
    return df_