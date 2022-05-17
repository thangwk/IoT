import pandas as pd

def IP_address_grouping(df):

    data = df.groupby(['EventID', 'SrcIP']).mean().reset_index()
    Highest_packet = data.groupby('SrcIP').sum().sort_values(by='TotalPacketCount', ascending=False).reset_index()[['SrcIP', 'TotalPacketCount']]
    Highest_packet.columns = ['SrcIP', 'TotalPacketCount']

    Highest_alerts = df.groupby('SrcIP').count().sort_values(by='EventType',ascending=False).reset_index()[['SrcIP','EventType']]
    Highest_alerts.columns = ['SrcIP','EventType']

    return Highest_packet, Highest_alerts