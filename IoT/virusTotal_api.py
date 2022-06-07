#import file where api key is stored at
#import config
import requests
import json

def api_call_virustotal(ip_address):
    ip_address = ip_address
    #api_key = config.virustotal_api_key
    #api_url = "https://www.virustotal.com/api/v3/search?query=" + ip_address
    api_url = "https://www.virustotal.com/ui/ip_addresses/" + ip_address
    '''
    headers = {
        "Accept": "application/json",
        "x-apikey": config.virustotal_api_key
    }
    '''
    headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36",
    "X-Tool": "vt-ui-main",
    "X-VT-Anti-Abuse-Header": "MTU1MzM0NDMwNjEtWkc5dWRDQmlaU0JsZG1scy0xNjU0NTg2NjkyLjMyMw==",
    "Referer": "https://www.virustotal.com/",

    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    }
    response = requests.get(api_url, headers=headers)
    return response

def read_response(response):
    j_data = json.loads(response.text)
    info = j_data['data']
    stats = info['attributes']['last_analysis_stats']

    harmless = stats.get('harmless', 0)
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get("timeout", 0)

    stats_output = (malicious + suspicious) / (malicious + suspicious + harmless + undetected + timeout)

    info = j_data['data']
    data = info['attributes']['last_analysis_results']

    new_list = []
    for i in data:
        if data[i]['category'] == 'malicious':
            new_list.append(data[i]['engine_name'])
    return stats_output, new_list, harmless, malicious, suspicious, undetected, timeout

''' Orgiginal
def api_call_virustotal(ip_address):
    ip_address = ip_address
    api_key = config.virustotal_api_key
    api_url = "https://www.virustotal.com/api/v3/search?query=" + ip_address
    headers = {
        "Accept": "application/json",
        "x-apikey": config.virustotal_api_key
    }
    response = requests.get(api_url, headers=headers)
    return response

def read_response(response):
    j_data = json.loads(response.text)
    info = j_data['data']
    stats = info[0]['attributes']['last_analysis_stats']

    harmless = stats.get('harmless', 0)
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get("timeout", 0)

    stats_output = (malicious + suspicious) / (malicious + suspicious + harmless + undetected + timeout)

    info = j_data['data']
    data = info[0]['attributes']['last_analysis_results']

    new_list = []
    for i in data:
        if data[i]['category'] == 'malicious':
            new_list.append(data[i]['engine_name'])
    return stats_output, new_list, harmless, malicious, suspicious, undetected, timeout
'''