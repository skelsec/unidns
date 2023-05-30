from unidns.protocol.structs import *
from unidns.network.packetizer import DNSPacketizer
from asysocks.unicomm.common.target import UniTarget
from asysocks.unicomm.client import UniClient
from typing import Dict
import asyncio
import os
import ipaddress

class DNSClient:
	def __init__(self, target:UniTarget, query_timeout:float = 0.5, connection_keepalive_time:float = 10):
		self.target = target
		self.connection_keepalive_time = connection_keepalive_time
		self.query_timeout = query_timeout
		self.cache = {}
		self.TID_lookup:Dict[bytes, asyncio.Future] = {}
		self.connection = None
		self.__keepalive_monitor_task = None
		self.__server_in_task = None

	async def __keepalive_monitor(self):
		while True:
			await asyncio.sleep(self.connection_keepalive_time)
			if self.connection is not None and len(self.TID_lookup) == 0:
				print("Closing connection")
				await self.connection.close()
				self.connection = None

	async def __handle_server_in(self):
		try:
			while self.connection is not None:
				async for packetdata in self.connection.read():
					packet = DNSPacket.from_bytes(packetdata)
					if packet.TransactionID not in self.TID_lookup:
						print("Unknown TID")
						continue
					self.TID_lookup[packet.TransactionID].set_result(packet)
		finally:
			for tid in self.TID_lookup:
				self.TID_lookup[tid].cancel()
			try:
				await self.connection.close()
			except:
				pass
			self.connection = None
	
	async def __server_request(self, question: DNSQuestion, with_recursion:bool = True):
		try:
			if self.connection is None:
				_, err = await self.__create_connection()
				if err is not None:
					return None, None, err

			packet = DNSPacket()
			packet.TransactionID = b'\x00\x00'
			packet.QR = DNSResponse.REQUEST
			packet.Rcode = DNSResponseCode.NOERR
			packet.FLAGS = DNSFlags.RD if with_recursion else DNSFlags(0)
			packet.Opcode = DNSOpcode.QUERY
			packet.Questions.append(question)
			if packet.to_bytes() in self.cache:
				return self.cache[packet.to_bytes()], None, None
			packet.TransactionID = os.urandom(2)
			answer_future = asyncio.Future()
			self.TID_lookup[packet.TransactionID] = answer_future
			await self.connection.write(packet.to_bytes())
			return answer_future, packet.TransactionID, None
		except Exception as e:
			return None, None, e

	async def __create_connection(self):
		try:
			for future in self.TID_lookup.values():
				future.cancel()
			self.TID_lookup = {}
			self.connection = None
			packetizer = DNSPacketizer()
			client = UniClient(self.target, packetizer)
			self.connection = await client.connect()
			self.__keepalive_monitor_task = asyncio.create_task(self.__keepalive_monitor())
			self.__server_in_task = asyncio.create_task(self.__handle_server_in())
			return True, None
		except Exception as e:
			return None, e
	
	async def run(self):
		# no actual need to call this, but you can check the connection
		return await self.__create_connection()

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