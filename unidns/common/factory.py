from asysocks.unicomm.common.target import UniTarget
from unidns.client import DNSClient
from unidns.common.settings import DNSSettings


class DNSConnectionFactory:
    def __init__(self, target:UniTarget):
        self.target = target
    
    def get_client(self, settings:DNSSettings = None):
        return DNSClient(self.target, settings)