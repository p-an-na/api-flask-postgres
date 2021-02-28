from configparser import ConfigParser


def configReader():
    config = ConfigParser()
    config.read('config.ini')
    return config