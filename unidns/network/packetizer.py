from asysocks.unicomm.common.packetizers import Packetizer

class DNSPacketizer(Packetizer):
	def __init__(self):
		Packetizer.__init__(self, 65535)
		self.in_buffer = b''
	
	def process_buffer(self):
		packet_length = -1
		while len(self.in_buffer) > 2:
			packet_length = int.from_bytes(self.in_buffer[:2], byteorder = 'big', signed=False)
			if len(self.in_buffer) < packet_length:
				break
			packet = self.in_buffer[2:packet_length+2]
			self.in_buffer = self.in_buffer[packet_length+2:]
			yield packet
		

	async def data_out(self, data):
		yield data

	async def data_in(self, data):
		if data is None:
			yield data
		self.in_buffer += data
		for packet in self.process_buffer():
			yield packet