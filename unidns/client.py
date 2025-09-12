from unidns.protocol.structs import *
from unidns.common.settings import DNSSettings
from unidns.network.packetizer import DNSPacketizer
from asysocks.unicomm.common.target import UniTarget, UniProto
from asysocks.unicomm.client import UniClient
from typing import Dict
import asyncio
import os
import ipaddress
import socket


class DNSClient:
	def __init__(self, target:UniTarget, settings:DNSSettings = None):
		self.target = target
		if settings is None:
			settings = DNSSettings()
		self.connection_keepalive_time = settings.connection_keepalive_time
		self.query_timeout = settings.query_timeout
		self.cache = {}
		self.TID_lookup:Dict[bytes, asyncio.Future] = {}
		self.TID_lookup_packet:Dict[bytes, bytes] = {}
		self.connection = None
		self.__server_in_task = None

	
	async def __aenter__(self):
		return self
	
	async def __aexit__(self, exc_type, exc_val, exc_tb):
		if self.connection is not None:
			if asyncio.iscoroutine(self.connection.close):
				await self.connection.close()
			else:
				self.connection.close()
		self.connection = None
		if self.__server_in_task is not None:
			self.__server_in_task.cancel()
		for tid in self.TID_lookup:
			self.TID_lookup[tid].cancel()
		self.TID_lookup = {}

	async def __handle_server_in_udp(self):
		try:
			async for res in self.connection.read(with_addr = True):
				if res is None:
					break
				packetdata, addr = res
				if packetdata is None:
					break
				
				try:
					packet = DNSPacket.from_bytes(packetdata)
					await self.__process_packet(packet)
				except Exception as e:
					print("Error parsing packet:", e)
		finally:
			for tid in self.TID_lookup:
				self.TID_lookup[tid].cancel()
			try:
				if asyncio.iscoroutine(self.connection.close):
					await self.connection.close()
				else:
					self.connection.close()
			except:
				pass
			self.connection = None

	async def __handle_server_in_tcp(self):
		try:
			async for packetdata in self.connection.read():
				if packetdata is None:
					break
				packet = DNSPacket.from_bytes(packetdata)
				await self.__process_packet(packet)
		finally:
			for tid in self.TID_lookup:
				self.TID_lookup[tid].cancel()
			if self.connection is not None:
				await self.connection.close()
			self.connection = None

	async def __process_packet(self, packet:DNSPacket):
		if packet.TransactionID not in self.TID_lookup:
			#print("Unknown TID")
			return
		if packet.TransactionID in self.TID_lookup_packet:
			cachedata = self.TID_lookup_packet[packet.TransactionID]
			self.cache[cachedata] = packet
			del self.TID_lookup_packet[packet.TransactionID]
		self.TID_lookup[packet.TransactionID].set_result(packet)
	
	async def __server_request(self, question: DNSQuestion, with_recursion:bool = True):
		try:
			packet = DNSPacket(proto=socket.SOCK_DGRAM if self.target.protocol == UniProto.CLIENT_UDP else socket.SOCK_STREAM)
			packet.TransactionID = b'\x00\x00'
			packet.QR = DNSResponse.REQUEST
			packet.Rcode = DNSResponseCode.NOERR
			packet.FLAGS = DNSFlags.RD if with_recursion else DNSFlags(0)
			packet.Opcode = DNSOpcode.QUERY
			packet.Questions.append(question)
			cache_lookup_bytes = packet.to_bytes()
			if cache_lookup_bytes in self.cache:
				answer_future = asyncio.Future()
				answer_future.set_result(self.cache[cache_lookup_bytes])
				return answer_future, None, None
			tid = os.urandom(2)
			self.TID_lookup_packet[tid] = cache_lookup_bytes
			packet.TransactionID = tid
			answer_future = asyncio.Future()
			self.TID_lookup[tid] = answer_future
			if self.connection is None:
				_, err = await self.__create_connection()
				if err is not None:
					return None, None, err
			await self.connection.write(packet.to_bytes())
			return answer_future, packet.TransactionID, None
		except Exception as e:
			return None, None, e

	async def __create_connection(self):
		try:
			packetizer = DNSPacketizer()
			client = UniClient(self.target, packetizer)
			self.connection = await client.connect()
			if self.target.protocol == UniProto.CLIENT_TCP:
				self.__server_in_task = asyncio.create_task(self.__handle_server_in_tcp())
			else:
				self.__server_in_task = asyncio.create_task(self.__handle_server_in_udp())
			return True, None
		except Exception as e:
			return None, e

	async def query(self, name, qtype:str, with_recursion:bool = True):
		qtype = qtype.upper()
		if qtype == 'A':
			return await self.query_A(name)
		elif qtype == 'AAAA':
			return await self.query_AAAA(name)
		elif qtype == 'PTR':
			return await self.query_PTR(name)
		else:
			return None, Exception('Query type "%s" is not supported. Use A/AAAA/PTR')
		
	async def query_A(self, hostname:str, with_recursion:bool = True):
		tid = None
		try:
			question = DNSQuestion()
			question.QNAME = DNSName(str(hostname))
			question.QTYPE = DNSType.A
			answer_future, tid, err = await self.__server_request(question, with_recursion=with_recursion)
			if err is not None:
				return None, err
			res = await asyncio.wait_for(answer_future, self.query_timeout)
			if res.Rcode != DNSResponseCode.NOERR:
				return None, Exception("DNS error: {}".format(res.Rcode))
			for answer in res.Answers:
				if answer.TYPE == DNSType.A:
					return answer.ipaddress, None
			return None, Exception("No matching record found in response")
		except Exception as e:
			return None, e
		finally:
			if tid is not None and tid in self.TID_lookup:
				del self.TID_lookup[tid]
	
	async def query_AAAA(self, hostname:str, with_recursion:bool = True):
		tid = None
		try:
			question = DNSQuestion()
			question.QNAME = DNSName(str(hostname))
			question.QTYPE = DNSType.AAAA
			answer_future, tid, err = await self.__server_request(question, with_recursion=with_recursion)
			if err is not None:
				return None, err
			res = await asyncio.wait_for(answer_future, self.query_timeout)
			if res.Rcode != DNSResponseCode.NOERR:
				return None, Exception("DNS error: {}".format(res.Rcode))
			for answer in res.Answers:
				if answer.TYPE == DNSType.AAAA:
					return answer.ipaddress, None
			return None, Exception("No matching record found in response")
		except Exception as e:
			return None, e
		finally:
			if tid is not None and tid in self.TID_lookup:
				del self.TID_lookup[tid]
	
	async def query_PTR(self, ip:str or ipaddress.IPv4Address or ipaddress.IPv6Address, with_recursion:bool = True):
		tid = None
		try:
			if isinstance(ip, str):
				try:
					ip = ipaddress.ip_address(ip)
				except:
					raise Exception("Invalid IP address")
			question = DNSQuestion()
			question.QNAME = DNSName(str(ip.reverse_pointer))
			question.QTYPE = DNSType.PTR
			answer_future, tid, err = await self.__server_request(question, with_recursion=with_recursion)
			if err is not None:
				return None, err
			res = await asyncio.wait_for(answer_future, self.query_timeout)
			if res.Rcode != DNSResponseCode.NOERR:
				return None, Exception("DNS error: {}".format(res.Rcode))
			for answer in res.Answers:
				if answer.TYPE == DNSType.PTR:
					return answer.domainname, None
			return None, Exception("No matching record found in response")
		except Exception as e:
			return None, e
		finally:
			if tid is not None and tid in self.TID_lookup:
				del self.TID_lookup[tid]

	async def query_SOA(self, hostname:str, with_recursion:bool = True):
		tid = None
		try:
			question = DNSQuestion()
			question.QNAME = DNSName(str(hostname))
			question.QTYPE = DNSType.SOA
			answer_future, tid, err = await self.__server_request(question, with_recursion=with_recursion)
			if err is not None:
				return None, err
			res = await asyncio.wait_for(answer_future, self.query_timeout)
			if res.Rcode != DNSResponseCode.NOERR:
				return None, Exception("DNS error: {}".format(res.Rcode))
			for answer in res.Answers:
				if answer.TYPE == DNSType.SOA:
					return answer, None
			return None, Exception("No matching record found in response")
		except Exception as e:
			return None, e
		finally:
			if tid is not None and tid in self.TID_lookup:
				del self.TID_lookup[tid]

if __name__ == "__main__":
	

	async def main():
		for protocol in [UniProto.CLIENT_UDP, UniProto.CLIENT_TCP]:
			client = DNSClient(UniTarget("8.8.8.8", 53, protocol=protocol))
			res = await client.query("google.com", "A")
			print(res)
			await asyncio.sleep(10)
			res = await client.query("google.com", "A")
			print(res)
			res = await client.query("index.hu", "A")
			print(res)
			await asyncio.sleep(10)
			res = await client.query("index.hu", "A")
			print(res)
			await asyncio.sleep(10)
			res = await client.query("444.hu", "A")
			print(res)
			await asyncio.sleep(10)
			res = await client.query("444.hu", "A")

		for protocol in [UniProto.CLIENT_UDP, UniProto.CLIENT_TCP]:
			client = DNSClient(UniTarget("8.8.8.8", 53, protocol=protocol))
			res = await client.query("google.com", "A")
			print(res)
			res = await client.query("google.com", "A")
			print(res)
			res = await client.query("index.hu", "A")
			print(res)
			res = await client.query("index.hu", "A")
			print(res)
			res = await client.query("444.hu", "A")
			print(res)
			res = await client.query("444.hu", "A")
	asyncio.run(main())
