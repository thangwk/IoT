from dateutil import parser
from datetime import datetime, timedelta
import json
import config
import requests
import pandas as pd

def opensearch_request_SG(start_date, end_date):
    """function to find ip address in SG
    date to be in format as listed YYYY-MM-DD
    returns 4 values: URL, hashes, time_start,time_end """
    # load basic json request text file
    json_file = open(r"C:\Data_Science_Projects\IoT\IoT\IoT\OS_SG_json.txt")
    json_request = json.load(json_file)

    date_time = parser.parse(start_date)
    new_date = date_time + timedelta(days=1)
    start_date = str(datetime.strftime(new_date,("%Y-%m-%d")))

    # set ip address
    #json_request['params']['body']['query']['bool']['filter'][0]['bool']['filter'][0]['multi_match']['query'] = ip

    # set command to find
    # json_request['params']['body']['query']['bool']['filter'][0]['bool']['filter'][1]['multi_match']['query']

    # start time
    # 2022-03-02T15:59:59.999Z is 2022 03-02 00:00hours
    json_request['params']['body']['query']['bool']['filter'][3]['range']['startTime']['gte'] = start_date + "T16:00:00.000Z"

    # end time
    # 2022-03-03T15:59:59.999Z is 2022 03-03 23:59hours
    json_request['params']['body']['query']['bool']['filter'][3]['range']['startTime']['lte'] = end_date + "T15:59:59.999Z"

    headers = {
        'osd-xsrf': 'true',
        'content-type': 'application/json'
    }

    data = config.Opensearch_API_key

    #log in get session cookie
    response = requests.post('https://os.gcaaide.org/_dashboards/auth/login', headers=headers, json=data)
    cookie_key = response.headers['set-cookie'].split()[0]

    headers = {
        'osd-xsrf': 'true',
        'content-type': 'application/json',
        'cookie': cookie_key
    }
    # take the session cookie and do search based on parameters required.
    response = requests.post('https://os.gcaaide.org/_dashboards/internal/search/opensearch', headers=headers,
                             json=json_request)
    response_json = response.content.decode('utf-8').replace('\0', '')
    struct = json.loads(response_json)
    if struct['rawResponse']['hits']['total'] < 1:
        data = [[ip, 'None', 'None', 'None','None', 'None', 'None', 'None','None', 'None', 'None']]
        output = pd.DataFrame(data, columns = ['Source IP','Source Port','loggedin','Dest IP','Dest Port'\
                                           ,'Source Country','Commands','urls','hashes','startTime','stopTime'])
        return output
    # print(struct)
    df = pd.json_normalize(struct)

    test = df['rawResponse.hits.hits'][0]
    # print(test)
    df1 = pd.json_normalize(test)

    output = df1[['_source.peerIP','_source.peerPort','_source.loggedin','_source.hostIP','_source.hostPort', '_source.geoip.country_code2','_source.commands','_source.urls','_source.hashes','_source.startTime','_source.endTime']]
    output.columns=['Source IP','Source Port','loggedin','Dest IP','Dest Port','Source Country','Commands','urls','hashes','startTime','stopTime']
    return output