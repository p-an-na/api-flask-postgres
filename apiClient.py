import logging
import requests
from config_read import configReader


def get_api_endpoint(path):
    config = configReader()
    url = config['url']['api_endpoint']
    return url + path

def get_country(ip_address):
    config = configReader()
    params = config['auth']['acces_key']
    response = requests.get(get_api_endpoint(ip_address), params = params)
    logging.debug('Response get ticket:', response.text, 'Response status code:', response.status_code)
    status_code = response.status_code
    response = response.json()
    return response, status_code