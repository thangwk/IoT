import pandas as pd
import json
import requests
import config


def opensearch_request(start_date, end_date, ip):
    """function to find ip address that is doing a "wget" based on IP
    start date to be in format as listed 2022-03-01T16:00:00.000Z for 2022 03-02 00:00hours
    end date to be 2022-03-17T15:59:59.999Z for 2022 03-17
    IP = "xxx.xxx.xxx.xxx" format
    returns 4 values: URL, hashes, time_start,time_end """
    # load basic json request
    json_file = open(r"D:\Data\OpenSearch query\OpenSearch_json.txt")
    json_request = json.load(json_file)

    # set ip address
    json_request['params']['body']['query']['bool']['filter'][0]['bool']['filter'][0]['multi_match']['query'] = ip

    # set command to find
    # json_request['params']['body']['query']['bool']['filter'][0]['bool']['filter'][1]['multi_match']['query']

    # start time
    # 2022-03-02T15:59:59.999Z is 2022 03-02 00:00hours
    json_request['params']['body']['query']['bool']['filter'][1]['range']['startTime']['gte'] = start_date

    # end time
    # 2022-03-03T15:59:59.999Z is 2022 03-03 23:59hours
    json_request['params']['body']['query']['bool']['filter'][1]['range']['startTime']['lte'] = end_date

    headers = {
        'osd-xsrf': 'true',
        'content-type': 'application/json'
    }

    data = config.data


    response = requests.post('https://os.gcaaide.org/_dashboards/auth/login', headers=headers, json=data)
    cookie_key = response.headers['set-cookie'].split()[0]

    headers = {
        'osd-xsrf': 'true',
        'content-type': 'application/json',
        'cookie': cookie_key
    }

    # data = '{"params":{"index":"gca-honeyfarm-1-*,gca-honeyfarm-2-*","body":{"version":true,"size":500,"sort":[{"startTime":{"order":"desc","unmapped_type":"boolean"}}],"aggs":{"2":{"date_histogram":{"field":"startTime","fixed_interval":"12h","time_zone":"Asia/Singapore","min_doc_count":1}}},"stored_fields":["*"],"script_fields":{},"docvalue_fields":[{"field":"@timestamp","format":"date_time"},{"field":"endTime","format":"date_time"},{"field":"startTime","format":"date_time"}],"_source":{"excludes":[]},"query":{"bool":{"must":[],"filter":[{"bool":{"should":[{"match":{"commands":"busybox"}}],"minimum_should_match":1}},{"exists":{"field":"commands"}},{"range":{"startTime":{"gte":"2022-02-23T06:12:24.843Z","lte":"2022-03-23T06:12:24.843Z","format":"strict_date_optional_time"}}}],"should":[],"must_not":[]}},"highlight":{"pre_tags":["@opensearch-dashboards-highlighted-field@"],"post_tags":["@/opensearch-dashboards-highlighted-field@"],"fields":{"*":{}},"fragment_size":2147483647}},"preference":1648009227085}}'
    # data = '{"params":{"index":"gca-honeyfarm-1-*","body":{"version":true,"size":500,"sort":[{"startTime":{"order":"desc","unmapped_type":"boolean"}}],"aggs":{"2":{"date_histogram":{"field":"startTime","fixed_interval":"30s","time_zone":"America/Los_Angeles","min_doc_count":1}}},"stored_fields":["*"],"script_fields":{},"docvalue_fields":[{"field":"@timestamp","format":"date_time"},{"field":"endTime","format":"date_time"},{"field":"startTime","format":"date_time"}],"_source":{"excludes":[]},"query":{"bool":{"must":[{"match_all":{}}],"filter":[{"range":{"startTime":{"gte":"2022-03-02T14:52:10.224Z","lte":"2022-03-02T15:07:10.224Z","format":"strict_date_optional_time"}}}],"should":[],"must_not":[]}},"highlight":{"pre_tags":["@opensearch-dashboards-highlighted-field@"],"post_tags":["@/opensearch-dashboards-highlighted-field@"],"fields":{"*":{}},"fragment_size":2147483647}},"preference":1646156231254}}'

    response = requests.post('https://os.gcaaide.org/_dashboards/internal/search/opensearch', headers=headers,
                             json=json_request)
    response_json = response.content.decode('utf-8').replace('\0', '')
    struct = json.loads(response_json)
    if struct['rawResponse']['hits']['total'] < 1:
        return 'None', 'None', 'None', 'None'
    # print(struct)
    df = pd.json_normalize(struct)

    test = df['rawResponse.hits.hits'][0]
    # print(test)
    df1 = pd.json_normalize(test)

    output = df1[['_source.peerIP','_source.peerPort','_source.loggedin','_source.hostIP','_source.hostPort', '_source.geoip.country_code2','_source.commands','_source.urls','_source.hashes','_source.startTime','_source.endTime']]
    output.columns=['Source IP','Source Port','loggedin','Dest IP','Dest Port','Source Country','Commands','urls','hashes','startTime','stopTime']
    return output
