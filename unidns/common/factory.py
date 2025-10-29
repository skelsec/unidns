from asysocks.unicomm.common.target import UniTarget
from unidns.client import DNSClient
from unidns.common.settings import DNSSettings


class DNSConnectionFactory:
    def __init__(self, target:UniTarget):
        self.target = target
    
    def get_client(self, settings:DNSSettings = None):
        return DNSClient(self.target, settings)
    
    async def test_connection(self, settings:DNSSettings = None):
        # must return True, None, None if connection is successful
        try:
            connection = self.get_client(settings)
            async with connection:
                _, err = await connection.query('google.com', 'A')
                if err is not None:
                    raise err
                return True, None, None
        except Exception as e:
            return False, None, e