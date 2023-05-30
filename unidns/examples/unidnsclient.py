from unidns.client import DNSClient
from asysocks.unicomm.common.target import UniTarget, UniProto
import asyncio

async def amain(host, port, domain, record_type, recursion = True):
    target = UniTarget(host, port, UniProto.CLIENT_TCP)
    client = DNSClient(target)
    response, error = await client.query(domain, record_type, recursion)
    if error is not None:
        print("Error: {}".format(error))
    else:
        print(response)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Issue DNS queries to a specified DNS server.")
    parser.add_argument("-a", "--address", type=str, required=True,
                        help="The IP address of the DNS server")
    parser.add_argument("-p", "--port", type=int, required=False, default = 53,
                        help="The port number of the DNS server")
    parser.add_argument("-d", "--domain", type=str, required=True,
                        help="The domain name for the DNS query")
    parser.add_argument("-t", "--type", type=str, choices=["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SRV", "TXT"],
                        default="A", help="The DNS record type for the query (default: A)")
    parser.add_argument("-r", "--recursion", action="store_true", help="Enable DNS recursion")
    
    args = parser.parse_args()
    asyncio.run(amain(args.address, args.port, args.domain, args.type, args.recursion))

if __name__ == '__main__':
    main()