"""
@Time ： 2020/11/3 19:22
@Auth ： Jier 
@Email：jwjier@gmail.com

"""
SG_DEF_DURATION = 10  # in seconds
LOCAL_PORT = 0
################################################################################
import numpy as np
import crcmod
from Crypto.Cipher import AES
import netifaces

import matlab.engine

import matplotlib.pylab as mp
import matplotlib.animation as ma
import os
import sys
import re
import time
import random
import pathlib
import urllib
from contextlib import suppress, closing
import os
import sys
import time
import socket
import select
import struct
import json
import base64
import hashlib
import ipaddress
import asyncio
from collections import OrderedDict
from typing import Any, Container, List, Tuple, Dict, Union, Optional, Coroutine, Iterator, Callable
try:
    from .sg_net import *
except ImportError:
    from sg_net import *

SG_CAPTURE_VERSION = "0.1.0"
SG_CAPTURE_VERINFO = "Audio capture tool v{} for SG+ Pickup\n".format(SG_CAPTURE_VERSION) + \
                     "Copyright (C) Focal Acoustics, 2020-2021."

################################################################################
SocketAddr = Tuple[str, int]
# Packet type
SG_PKT_TYPE_REQ = 1
SG_PKT_TYPE_RSP = 2
SG_PKT_TYPE_AUDIO = 3
SG_PKT_TYPE_AUDIO_ACK = 4
SG_PKT_TYPE_LANSRCH = 5
SG_PKT_TYPE_LANSRCH_RSP = 6
SG_PKT_HEADSZ = 8  # size of the packet header
SG_PKT_BUFSZ = 2048  # size of the packet buffer
SG_NET_SERVER_PORT = 2228
SG_LAN_SEARCH_PORT = 2229
SG_AUDIO_PCMS8 = 1
SG_AUDIO_PCMS16LE = 2
SG_AUDIO_PCMS24LE = 3
SG_AUDIO_PCMS32LE = 4
SG_AUDIO_OPUS = 10
SG_DEF_PASSWORD = "12345678"
SG_DEF_SECURITY_KEY = b'\x8E\x75\x9C\x0A\x29\xEB\xA7\xE3\x48\x42\x8D\x86\xF5\x87\xE5\x8C'
eng = matlab.engine.start_matlab()

# define figure
mp.figure("Signal", facecolor='lightgray')
mp.title('Signal', fontsize=20)
mp.xlabel('Time', fontsize=14)
mp.ylabel('Signal', fontsize=14)

ax = mp.gca()
ax.set_ylim(-8388608, 8388608)
ax.set_xlim(0, 321)

pl = mp.plot([], [], c="orangered")[0]
pl.set_data([], [])


class SgDevice:
    def __init__(self):
        self.product_id: str = ""
        self.device_id: str = ""
        self.fw_version: str = ""
        self.device_name: str = ""
        self.mac_addr: str = ""
        self.ip_addr: str = ""


class SgAudioPacket:
    def __init__(self):
        self.session_id: int = 0
        self.sn: int = 0
        self.timestamp: int = 0
        self.output_channel: int = 0
        self.audio_encoder: int = 0
        self.audio_channels: int = 0
        self.audio_sample_rate: int = 0
        self.audio_frame_size: int = 0
        self.audio_sample_bits: int = 0
        self.payload_size: int = 0
        self.payload: Optional[bytes] = None


class SgParser:
    def __init__(self, *, buffer: Optional[memoryview] = None):
        self.m_buffer = buffer or memoryview(bytearray(SG_PKT_BUFSZ))
        self.m_crypter: object = None
        self.m_reader: Optional[asyncio.StreamReader] = None
        self.m_writer: Optional[asyncio.StreamWriter] = None
        self.m_crc: object = crcmod.predefined.Crc('modbus')

    def buffer(self) -> memoryview:
        return self.m_buffer

    def crypter(self, crypter: object) -> object:
        return self.m_crypter

    def set_crypter(self, crypter: object):
        self.m_crypter = crypter

    def set_password(self, password: str):
        self.m_crypter = AES.new(SgParser.generate_key(password), AES.MODE_ECB)

    def set_key(self, security_key: bytes):
        self.m_crypter = AES.new(security_key, AES.MODE_ECB)

    def reader(self) -> asyncio.StreamReader:
        return self.m_reader

    def writer(self) -> asyncio.StreamWriter:
        return self.m_writer

    def set_streams(self,
                    reader: asyncio.StreamReader,
                    writer: asyncio.StreamWriter):
        self.m_reader = reader
        self.m_writer = writer

    def close_streams(self):
        self.m_reader = None
        if self.m_writer is not None:
            self.m_writer.close()
            self.m_writer = None

    # Build a packet
    def build_packet(self,
                     req: Union[dict, bytes, bytearray, memoryview],
                     packet_type: int = SG_PKT_TYPE_REQ,
                     *,
                     crc_off: Optional[bool] = None) -> memoryview:
        assert self.m_crypter
        buf = self.m_buffer

        if isinstance(req, dict):
            payload = json.dumps(req).encode()
        else:
            payload = req

        # Copy payload
        size = SG_PKT_HEADSZ + len(payload)
        # Do not copy if payload is store in the same buffer
        if not (isinstance(req, memoryview) and req.obj is buf):
            buf[SG_PKT_HEADSZ:size] = payload

        # Appand padding zero: len(payload) == 0 (mod 16)
        padding = -(size - SG_PKT_HEADSZ) & 15
        if padding:
            end = size + padding
            buf[size:end] = b'\0' * padding
            size = end

        # Fill header
        struct.pack_into('<HHHB', buf, 0,
                         0x7E7E,
                         size,
                         0,
                         packet_type
                         )

        # Calculate CRC
        self.m_crc.crcValue = 0xFFFF
        if not crc_off:
            self.m_crc.update(buf[6:size])
        struct.pack_into('<H', buf, 4, self.m_crc.crcValue)

        buf[SG_PKT_HEADSZ:size] = self.m_crypter.encrypt(buf[SG_PKT_HEADSZ:size])
        return buf[:size]

    def build_audio_ack(self,
                        session_id: int,
                        sn_list: List[int],
                        *,
                        crc_off: Optional[bool] = None) -> memoryview:
        n = len(sn_list)
        struct.pack_into(
            '<IHH{}I'.format(n),
            self.m_buffer,
            SG_PKT_HEADSZ,
            session_id,
            n,
            0,
            *sn_list)
        n = SG_PKT_HEADSZ + 8 + 4 * n
        return self.build_packet(self.m_buffer[SG_PKT_HEADSZ:n], SG_PKT_TYPE_AUDIO_ACK, crc_off=crc_off)

    def parse_packet(self,
                     packet: Union[bytes, bytearray, memoryview],
                     *,
                     crc_off: Optional[bool] = None
                     ) -> Union[dict, SgAudioPacket]:
        if isinstance(packet, bytes):
            n = len(packet)
            self.m_buffer[:n] = packet
            packet = self.m_buffer[:n]
        elif isinstance(packet, bytearray):
            packet = memoryview(packet)
        return self.parse_packet2(packet[:SG_PKT_HEADSZ], packet[SG_PKT_HEADSZ:], crc_off=crc_off)

    # Parse a packet's header and payload
    def parse_packet2(self,
                      header: Union[bytes, bytearray, memoryview],
                      payload: Union[bytes, bytearray, memoryview],
                      *,
                      crc_off: Optional[bool] = None
                      ) -> Union[dict, SgAudioPacket]:
        assert self.m_crypter

        magic, size, chksum, packet_type = struct.unpack_from('<HHHB', header, 0)
        if magic != 0x7E7E or size != len(payload) + SG_PKT_HEADSZ:
            raise ValueError('Packet error.')

        payload_size = size - SG_PKT_HEADSZ

        if packet_type in (SG_PKT_TYPE_RSP, SG_PKT_TYPE_LANSRCH_RSP):
            # Non-audio
            if payload_size % 16 != 0:
                raise ValueError('Payload length error.')
            # AES decrypt
            payload = self.m_crypter.decrypt(payload)
        elif packet_type == SG_PKT_TYPE_AUDIO:
            # Audio
            if payload_size < 36:
                raise ValueError('Payload length error.')
            # AES decrypt
            payload[4:36] = self.m_crypter.decrypt(payload[4:36])
        else:
            raise ValueError('Packet type error.')

        if not crc_off:
            cm = self.m_crc
            cm.crcValue = 0xFFFF
            cm = crcmod.predefined.Crc('modbus')
            cm.update(header[6:SG_PKT_HEADSZ])
            cm.update(payload)
            if cm.crcValue != chksum:
                raise ValueError('CRC error.')

        if packet_type in (SG_PKT_TYPE_RSP, SG_PKT_TYPE_LANSRCH_RSP):
            # Non-audio, parse JSON
            end = payload.rfind(b'}') + 1
            return json.loads(payload[:end]) if end > 0 else {}

        # Parse audio packet
        apk = SgAudioPacket()
        (apk.session_id, \
         apk.sn,
         apk.timestamp,
         _,
         apk.output_channel,
         apk.audio_encoder,
         apk.audio_channels,
         apk.audio_sample_rate,
         apk.audio_frame_size,
         apk.audio_sample_bits,
         xor_key,
         apk.payload_size) = struct.unpack_from('<IIQBBBBIHBBH', payload, 0)
        if apk.payload_size + 30 > len(payload):
            raise ValueError('Audio packet error.')
        # Decrypt the payload by <xor_key>
        apk.payload = (np.frombuffer(payload[30: 30 + apk.payload_size], dtype=np.uint8) ^ xor_key).tobytes()
        return apk

    async def connect(self,
                      host: str,
                      port: int = SG_NET_SERVER_PORT):
        reader, writer = await asyncio.open_connection(host, port)
        sock = writer.get_extra_info('socket')
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.set_streams(reader, writer)

    async def read(self) -> Tuple[bytes, bytes]:
        assert self.m_reader
        # Read header.
        header = await self.m_reader.readexactly(SG_PKT_HEADSZ)
        magic, size = struct.unpack_from('<HH', header, 0)
        if magic != 0x7E7E or size > SG_PKT_BUFSZ:
            raise ValueError('Packet error.')
        # Read payload.
        payload = await self.m_reader.readexactly(size - SG_PKT_HEADSZ)
        return (header, payload)

    async def request(self,
                      req: Union[dict, bytes, bytearray, memoryview],
                      packet_type: int = SG_PKT_TYPE_REQ,
                      ) -> Union[dict, SgAudioPacket]:
        assert self.m_writer
        # Build the packet.
        pkt = self.build_packet(req, packet_type)
        # Send the packet and wait done.
        self.m_writer.write(pkt)
        # await self.m_writer.drain()
        if packet_type == SG_PKT_TYPE_REQ:
            # Read the response if needed.
            header, payload = await self.read()
            return self.parse_packet2(header, payload)
        return None

    @staticmethod
    def generate_key(password: str) -> bytes:
        m = hashlib.md5()
        m.update(password.encode())
        m.update(b'\xFD\x50\xF7\x22\x8C\x8F\x10\x1B\x2C\x89\x89\x40\x2B\x0F\x15\x8F')
        return m.digest()


class SgAudioRetran:
    TIMEOUT = 1.0  # seconds
    MIN_INTERVAL = 0.05
    MAX_INTERVAL = 0.10

    def __init__(self, sn: int, packet: SgAudioPacket, start: float):
        self._times = 0
        self.sn = sn
        self.packet = packet
        self.start = start
        self.stop = start + self.TIMEOUT

    def next(self) -> bool:
        interval = self.MIN_INTERVAL * (1 << self._times)
        if interval <= self.MAX_INTERVAL:
            self._times += 1
        else:
            interval = self.MAX_INTERVAL
        self.start += interval
        return self.start <= self.stop


class SgDeviceSession:
    def __init__(self,
                 session_id: int,
                 device_ip: str,
                 password: str):
        self.id: int = session_id  # session ID
        self.device_addr: SocketAddr = (device_ip, 0)
        self.parser: SgParser = SgParser()
        self.parser.set_password(password)

        # Statistics
        self.incoming_bytes: int = 0
        self.incoming_packets: int = 0
        self.dup_packets: int = 0  # Duplicate packets
        self.lost_packtes: int = 0
        self.outgoing_acks: int = 0

        self.m_audio_parser: Optional[SgParser] = None
        self.m_session_key: Optional[bytes] = None  # session key
        self.m_retrans: Dict[int, SgAudioRetran] = dict()
        self.m_first_sn: int = 0
        self.m_first_ts: int = 0  # the timestamp of the first packet
        self.m_next_sn: Optional[int] = None
        self.m_timestamp: int = 0  # the timestamp of the last packet
        self.m_now: float = 0.
        self.m_writer: Any = None
        self.m_audio_crc_off: bool = False
        self.m_log_enabled: bool = False

    def enable_log(self, enabled: bool):
        self.m_log_enabled = enabled

    def logi(self, text: str, *, flush: bool = False):
        pass
        # print(text, end='', flush=flush)

    def get_audio_parser(self):
        if self.m_audio_parser is None:
            self.m_audio_parser = SgParser(buffer=self.parser.buffer())
            self.m_audio_parser.set_key(self.m_session_key)
        return self.m_audio_parser

    def close(self):
        self.m_session_key = None
        self.m_retrans.clear()
        # Close writer.
        if hasattr(self.m_writer, 'close'):
            self.m_writer.close()
        self.m_writer = None
        # Close TCP connection.
        self.parser.close_streams()

    async def request(self, req: dict) -> dict:
        conntected = False
        while not conntected:
            if self.parser.writer() is None:
                conntected = True
                await self.parser.connect(self.device_addr[0])
            try:
                return await self.parser.request(req)
            except (OSError, EOFError):
                self.parser.close_streams()
                if conntected:
                    raise

    async def start_capture(self,
                            audio_params: dict,
                            create_writer: callable):
        # New a session key.
        session_key = os.urandom(16)
        # Start audio transmission.
        self.m_audio_crc_off = audio_params.get('audio_checksum') == 'off'
        req = dict(
            cmd='open_audio',
            session_id=self.id,
            session_key=base64.b64encode(session_key).decode(),
            **audio_params,
        )
        str = json.dumps(req)
        rsp = await self.request(req)
        if rsp['err_code'] != 0:
            if self.m_log_enabled:
                self.logi('  *** {}\n'.format(rsp['err_msg']))
            raise IOError(rsp['err_code'], rsp['err_msg'])

        if 'audio_channels' in rsp:
            audio_params.update(rsp)
        self.m_writer = create_writer(audio_params)
        # Set session key to start.
        self.m_session_key = session_key
        self.m_first_sn = 0
        self.m_first_ts = 0
        self.m_next_sn = None
        self.m_timestamp = 0
        # Initialize statistics.
        self.incoming_bytes = 0
        self.incoming_packets = 0
        self.dup_packets = 0
        self.lost_packtes = 0
        self.outgoing_acks = 0

    async def stop_capture(self):
        self.m_session_key = None
        self.m_retrans.clear()
        # Close writer.
        if hasattr(self.m_writer, 'close'):
            self.m_writer.close()
        self.m_writer = None
        try:
            await self.request(dict(cmd='close_audio', session_id=self.id))
        except:
            pass

    def recv_audio_packet(self,
                          transport: asyncio.DatagramTransport,
                          data: Union[bytes, bytearray, memoryview],
                          addr: SocketAddr):
        # Do not receive packet if this session has not been started.
        if self.m_session_key is None:
            return

        # Parse packet.
        packet = self.get_audio_parser().parse_packet(data, crc_off=self.m_audio_crc_off)
        self.device_addr = addr

        is_duplicate = False
        self.m_now = time.monotonic()
        while True:
            if self.m_next_sn is None:
                # Wait for the first packet of a frame.
                if not (packet.timestamp == 0 or (((self.m_first_sn + 1) & 0xFFFFFFFF) == packet.sn and
                                                  self.m_first_ts < packet.timestamp)):
                    self.m_first_sn = packet.sn
                    self.m_first_ts = packet.timestamp
                    break
                self.m_next_sn = packet.sn
                self.m_timestamp = packet.timestamp

            lost_num = (packet.sn - self.m_next_sn) & 0xFFFFFFFF
            if lost_num & 0x80000000:
                lost_num -= 0x100000000
            if (packet.timestamp >= self.m_timestamp + SgAudioRetran.TIMEOUT * 1000 or
                    lost_num >= 250):
                # Too many lost packges
                self.m_first_sn = packet.sn
                self.m_first_ts = packet.timestamp
                self.m_next_sn = None
                self.m_timestamp = 0
                self.m_retrans.clear()
                self.lost_packtes += lost_num
                if self.m_log_enabled:
                    self.logi('*** {}: drop packets before {}\n'.format(self.id, packet.sn))
                break

            if lost_num > 0:
                # Some packets lost
                for i in range(0, lost_num):
                    sn = (self.m_next_sn + i) & 0xFFFFFFFF
                    if sn not in self.m_retrans:
                        self.m_retrans[sn] = SgAudioRetran(sn, None, self.m_now)
            elif lost_num < 0:
                is_duplicate = True
                break

            rt = self.m_retrans.get(packet.sn)
            if rt is None:
                self.m_retrans[packet.sn] = SgAudioRetran(packet.sn, packet, self.m_now)
            elif rt.packet is None:
                rt.packet = packet
            else:
                is_duplicate = True
            break
        if is_duplicate:
            self.dup_packets += 1
            if self.m_log_enabled:
                self.logi('*** {}: duplicate packet {}\n'.format(self.id, packet.sn))
        # Process received packets and send ACK if there are lost packets.
        self._process_audio(transport)

    def send_audio_ack(self, transport: asyncio.DatagramTransport):
        if not self.m_retrans:
            return
        sn_list = []
        lost_list = []
        for sn, rt in self.m_retrans.items():
            if rt.packet is None:
                send_ack = False
                # Loop until the packet's next retransmission time is after now.
                while rt.start < self.m_now:
                    send_ack = True
                    if not rt.next():
                        # timed-out
                        lost_list.append(rt.sn)
                        send_ack = False
                        break
                if send_ack:
                    sn_list.append(rt.sn)
        for sn in lost_list:
            del self.m_retrans[sn]
            self.lost_packtes += 1
            if self.m_log_enabled:
                self.logi('*** {}: packet {} is timed-out\n'.format(self.id, rt.sn))
        if sn_list:
            pkt = self.get_audio_parser().build_audio_ack(self.id, sn_list, crc_off=self.m_audio_crc_off)
            transport.sendto(pkt, self.device_addr)
            self.outgoing_acks += 1
            if self.m_log_enabled:
                self.logi('*** {}: ACK {}\n'.format(self.id, sn_list))

    def _process_audio(self, transport: asyncio.DatagramTransport):
        while True:
            rt = self.m_retrans.get(self.m_next_sn)
            if rt is None or rt.packet is None:
                break
            pkt = rt.packet
            del self.m_retrans[self.m_next_sn]
            self.m_next_sn += 1
            self.m_timestamp = pkt.timestamp

            self.incoming_packets += 1
            self.incoming_bytes += len(pkt.payload)
            if self.m_log_enabled:
                self.logi(".", flush=True)
            # Write PCM data to stream.
            cr = self.m_writer.write(pkt.payload)
            if asyncio.iscoroutine(cr):
                asyncio.create_task(cr)
        self.send_audio_ack(transport)


class SgTimer:
    def __init__(self, interval: float, callback: callable):
        self.m_interval = interval
        self.m_callback = callback
        self.m_task = asyncio.create_task(self._job())

    def cancel(self):
        if self.m_task is not None:
            self.m_task.cancel()
            self.m_task = None

    async def _job(self):
        while True:
            await asyncio.sleep(self.m_interval)
            cr = self.m_callback()
            if asyncio.iscoroutine(cr):
                await cr


class SRP_PHAT():

    def __init__(self, pos):
        self.algName = "SRP-PHAT"
        self.pos = np.array(pos)
        self.M = np.size(self.pos, 0)

        self.fs = 16000
        self.fMin = 0
        self.fMax = 255
        self.step = 0.5
        self.lamda = 0.9
        self.frmSize = 1024
        self.c = 340

        fBin = self.fs * (np.arange(self.fMin, self.fMax, 1, dtype='float32')) / self.frmSize
        fBin = np.append(fBin, self.fMax)
        self.theta = np.arange(0, 180, self.step, dtype='float32')
        theta = np.append(self.theta, 180)
        tauMat = np.cos(theta * np.pi / 180)[:, None] * self.pos[None, :] / self.c

        self.df = np.exp(-2j * np.pi * fBin[:, None, None] * tauMat[None, :, :])
        self.PhiyE = np.zeros([np.size(fBin, 0), self.M, self.M], dtype='float32')

    def rtProc(self, yFrm):
        # Step 1: compute covariance matrix and update the estimate
        yf = np.fft.fft(yFrm, self.frmSize, 1).transpose(1, 0)
        yf = yf / np.abs(yf)
        Phiy = yf[..., None] @ yf[:, None, :].conj()
        self.PhiyE = self.lamda * self.PhiyE + (1 - self.lamda) * Phiy[self.fMin:self.fMax + 1, :, :]

        # Step 2: compute the spatial spectrum
        self.Px = ((self.df.conj() @ self.PhiyE[:, :, :]) * self.df).sum(axis=(0, 2))

        # Step 3: update the process
        print("%.1f degree" % (self.theta[np.where(self.Px == np.max(self.Px))]))


def win_advfw_add_program_rule(program: str, *, check_only=False, force=False) -> bool:
    if sys.platform != 'win32':
        return True

    import subprocess
    import locale
    import re

    rule_name = '#@program [{}]'.format(re.sub('[\\\\/]', '/', re.sub('[\'\"]', '', program.lower())))

    rule_exists = False
    status = subprocess.call('netsh.exe advfirewall firewall show rule name="{}"'.format(rule_name),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    if status == 0:
        rule_exists = True
        if not force:
            return True
    if check_only:
        return False

    bat_script = (
        '::==============================================================================\n'
        '@echo off\n'
        'setlocal\n'
        'set GETADMIN_VBS=getadmin-%~n0.vbs\n'
        '"%SystemRoot%\\system32\\fltMc.exe" 1>nul 2>&1\n'
        'if %errorlevel% neq 0 ( goto UACPrompt ) else ( goto gotAdmin )\n'
        ':UACPrompt\n'
        'echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\\%GETADMIN_VBS%"\n'
        'echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\\%GETADMIN_VBS%"\n'
        'cscript.exe /nologo "%temp%\\%GETADMIN_VBS%"\n'
        'exit /b\n'
        ':gotAdmin\n'
        'if exist "%temp%\\%GETADMIN_VBS%" ( del "%temp%\\%GETADMIN_VBS%" )\n'
        'cd /d "%~dp0"\n'
        '::==============================================================================\n\n'
        'netsh.exe advfirewall firewall {} rule name="{}" {} dir=in action=allow program="{}"\n'
        'del /q "%~0"\n'
    ).format(
        'set' if rule_exists else 'add',
        rule_name,
        'new' if rule_exists else '',
        program
    )
    bat_name = os.path.join(os.path.expandvars('%temp%'),
                            'getadmin-{}.cmd'.format(os.path.split(__file__)[1].replace('.', '_')))
    with open(bat_name, "w", encoding=locale.getpreferredencoding()) as f:
        f.write(bat_script)
    status = subprocess.call('cmd.exe /c "{}"'.format(bat_name),
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
    return status == 0


################################################################################
def sg_get_local_ip(device_ip):
    # Get the proper local IP address.
    dev_ipaddr = ipaddress.IPv4Address(device_ip)
    with suppress(OSError):
        for if_name in netifaces.interfaces():
            with suppress(KeyError):
                addr_infos = netifaces.ifaddresses(if_name)[netifaces.AF_INET]
                for addr_info in addr_infos:
                    ip_addr = addr_info['addr']
                    if dev_ipaddr in ipaddress.ip_network(
                            '{}/{}'.format(ip_addr, addr_info['netmask']),
                            strict=False):
                        return ip_addr
    return None

##########
geo = [-0.125, -0.075, -0.025, 0.025, 0.075, 0.125]
alg = SRP_PHAT(pos=geo)
##########


class sg_audio_file_writer:
    def __init__(self, session):
        self.t = 0
        self.tempAllData = []
        self.channel1 = []
        self.channel2 = []
        self.channel3 = []
        self.channel4 = []
        self.channel5 = []
        self.channel6 = []
        self.x = []
        self.x_all = []
        self.m_file = None
        self.m_session = session

        # audio buffer
        self.audioBuffer = np.zeros([6, 1024])
        self.frmCount = 0

    def open(self, file_path: str):
        self.m_file = open(file_path, "wb")
        self.m_session.m_recved_bytes = 0

    def close(self):
        if self.m_file is not None:
            self.m_file.close()
            self.m_file = None

    def write(self, data: bytes):
        if self.m_file is not None:
            self.m_file.write(data)
            self.m_session.m_recved_bytes += len(data)

            tempdata = []

            # print(self.t)
            if self.t == 0:
                self.tempAllData = []
                self.channel1 = []
                self.channel2 = []
                self.channel3 = []
                self.channel4 = []
                self.channel5 = []
                self.channel6 = []
                x1 = []
                x2 = []
                x3 = []
                x4 = []
                x5 = []
                x6 = []

            self.t += 1
            if self.t == 1:
                self.tempAllData += data
            if self.t == 2:
                self.tempAllData += data
            if self.t == 3:
                self.tempAllData += data
            if self.t == 4:
                self.tempAllData += data
            if self.t == 5:
                self.tempAllData += data
                #print(len(self.tempAllData))
                #(self.t)
                self.t = 0

                for i in range(320):
                    self.channel1.append(
                        int.from_bytes(self.tempAllData[18 * i: 18 * i + 3], byteorder='little', signed=True))
                    self.channel2.append(
                        int.from_bytes(self.tempAllData[18 * i + 3: 18 * i + 6], byteorder='little', signed=True))
                    self.channel3.append(
                        int.from_bytes(self.tempAllData[18 * i + 6: 18 * i + 9], byteorder='little', signed=True))
                    self.channel4.append(
                        int.from_bytes(self.tempAllData[18 * i + 9: 18 * i + 12], byteorder='little', signed=True))
                    self.channel5.append(
                        int.from_bytes(self.tempAllData[18 * i + 12: 18 * i + 15], byteorder='little', signed=True))
                    self.channel6.append(
                        int.from_bytes(self.tempAllData[18 * i + 15: 18 * i + 18], byteorder='little', signed=True))
                x1 = np.array(self.channel1)
                x2 = np.array(self.channel2)
                x3 = np.array(self.channel3)
                x4 = np.array(self.channel4)
                x5 = np.array(self.channel5)
                x6 = np.array(self.channel6)

                self.x = np.array([x1,x2,x3,x4,x5,x6]) / pow(2, 23)
                self.audioBuffer[:, 0:704] = self.audioBuffer[:, 320:1024]
                self.audioBuffer[:, 704:1024] = self.x
                self.frmCount = (self.frmCount + 1) % 3
                if self.frmCount == 0:
                    alg.rtProc(self.audioBuffer)


def sg_audio_create_writer(session, file_path, dev_info, audio_params, no_timestamp=False):
    localtm = time.localtime()
    fn = "[{}]{}-{}k-{}ch-{}bit.pcm".format(
        re.sub(r'[\\/:\*\?"<>|]', '_', dev_info['device_name']),
        '' if no_timestamp else time.strftime("-D%Y%m%dT%H%M%S", localtm),
        audio_params['audio_sample_rate'] // 1000,
        audio_params['audio_channels'] or 1,
        audio_params['audio_sample_bits'],
    )

    if not file_path:
        file_path = fn
    elif file_path.endswith(os.path.pathsep) or file_path.endswith('/'):
        file_path += fn
    dir = os.path.split(file_path)[0]
    if dir and not os.path.isdir(dir):
        try:
            os.makedirs(dir, exist_ok=True)
        except OSError:
            print('  *** Can not make directory "{}".'.format(dir))
            raise

    AUDIO_ENCODER_DCT = {
        SG_AUDIO_PCMS8: 'PCMS8',
        SG_AUDIO_PCMS16LE: 'PCMS16LE',
        SG_AUDIO_PCMS24LE: 'PCMS24LE',
        SG_AUDIO_PCMS32LE: 'PCMS32LE',
        SG_AUDIO_OPUS: 'OPUS',
    }
    print('  Device info:')
    print('    Product ID:         {}'.format(dev_info['product_id']))
    print('    Device ID:          {}'.format(dev_info['device_id']))
    print('    Device Name:        {}'.format(dev_info['device_name']))
    print('    Firmware Version:   {}'.format(dev_info['fw_version']))
    print('')
    print('  Audio Capture:')
    print('    Listen address:     {}'.format(audio_params['server_addr']))
    print('  Audio File:')
    print('    Codec:              {}'.format(AUDIO_ENCODER_DCT[audio_params['audio_encoder']]))
    print('    Sample Rate:        {}kHz'.format(audio_params['audio_sample_rate'] // 1000))
    print('    Channels:           {}'.format(audio_params['audio_channels'] or 1))
    print('    Bits per Sample:    {}'.format(audio_params['audio_sample_bits']))
    print('    Bitrate:            {}kbps'.format(audio_params['audio_bitrate'] // 1000))
    print('    Timestamp:          {}'.format(time.strftime("%Y-%m-%d %H:%M:%S", localtm)))
    print('    Duration:           {} seconds'.format(options.duration))
    print('    File Name:          {}'.format(file_path))

    writer = sg_audio_file_writer(session)
    # Open file
    try:
        writer.open(file_path)
    except OSError:
        print(' *** Can not open file "{}".\n'.format(file_path))
        raise
    return writer


class SgCaptureProtocol(asyncio.DatagramProtocol):
    RECV_BUFSZ = 2 * 1024 * 1024

    def __init__(self):
        self.transport = None
        self.local_addr: Optional[Tuple[str, int]] = None
        self.m_sessions: Dict[int, SgDeviceSession] = {}

    def close(self):
        for session in self.m_sessions.values():
            session.close()
        self.m_sessions.clear()
        self.transport.close()

    def connection_made(self, transport):
        sock = transport.get_extra_info('socket')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.RECV_BUFSZ)
        self.transport = transport
        self.local_addr = transport.get_extra_info('sockname')

    def datagram_received(self, data, addr):
        try:
            # Drop some packets to test audio ACK.
            # if random.randint(0, 100) == 0:
            #    return

            # The session ID is not encrypted.
            sid, = struct.unpack_from('<I', data, SG_PKT_HEADSZ)
            session = self.m_sessions[sid]
            session.recv_audio_packet(self.transport, data, addr)
        except (struct.error, KeyError, ValueError, IndexError):
            pass

    def create_session(self, device_ip: str, password: str) -> SgDeviceSession:
        # Create a new session and register it.
        while True:
            sid = random.randint(1, 0xFFFFFFFE)
            if sid not in self.m_sessions:
                break
        session = SgDeviceSession(sid, device_ip, password)
        session.enable_log(True)
        self.m_sessions[session.id] = session
        return session

    def remove_session(self, session_id: int):
        session = self.m_sessions.get(session_id)
        if session is not None:
            session.close()
            del self.m_sessions[session_id]


async def sg_audio_capture(device_ip: str, options):
    parse_result = urllib.parse.urlsplit('//' + options.listen_addr)
    local_host = parse_result.hostname
    local_port = parse_result.port or LOCAL_PORT
    if not local_host:
        local_host = sg_get_local_ip(device_ip)
        if local_host is None:
            print('  *** The device and this PC are not in a same LAN.')
            return -1

    timer = SgTimer(0.2, lambda: None)
    try:
        try:
            _, capture = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: SgCaptureProtocol(),
                (local_host, local_port),
                family=socket.AF_INET
            )
        except OSError:
            print('  *** Can not bind the local UDP socket to address "{}:{}".'.format(local_host, local_port))
            return -1

        with closing(capture):
            try:
                session = capture.create_session(device_ip, options.password)
                dev_info = await session.request(dict(cmd='get_device_info'))
            except OSError:
                print('  *** Can not connect to the device "{}".'.format(device_ip))
                return -1

            try:
                audio_params = dict(
                    server_addr='udp://{}:{}'.format(*capture.local_addr),
                    output_channel=options.channels,
                    audio_encoder=SG_AUDIO_PCMS24LE,
                    audio_channels=options.channels,  # mono
                    audio_frame_size=320,  # samples per frame
                    audio_sample_rate=16000,
                    audio_sample_bits=24,
                    audio_bitrate=0,  # no use for PCM
                    retrans_timeout=1000,  # threshold of retransmission timeout, in milliseconds
                    audio_checksum='off',
                )
                await session.start_capture(audio_params,
                                            lambda params: sg_audio_create_writer(
                                                session,
                                                options.file_path,
                                                dev_info,
                                                params,
                                                options.no_timestamp)
                                            )
                SgTimer(options.duration, lambda: setattr(sys, 'app_terminated', True))
                while not getattr(sys, 'app_terminated', False):
                    await asyncio.sleep(0.1)
            finally:
                print('')
                # Close the session
                capture.remove_session(session.id)
                await session.stop_capture()
                if (getattr(session, 'm_recved_bytes', 0) == 0 and not
                win_advfw_add_program_rule(sys.executable, check_only=True)):
                    print(' *** Can not receive any audio frame.')
                    print(' Use --fw option to add a firewall rule.')
                    win_advfw_add_program_rule(sys.executable)
            return 0

    except (OSError, IOError, EOFError, ValueError) as e:
        if isinstance(e, (EOFError, ValueError)):
            print('  *** Can access the device.')
            print('  Please input the correct password with "-p" option.')
        return -3
    finally:
        timer.cancel()


def sg_capture_main(device_ip: str, options):


    loop = asyncio.get_event_loop()
    tasks = asyncio.gather(
        sg_audio_capture(device_ip, options),
    )
    while True:
        try:
            status, = loop.run_until_complete(tasks)
            break
        except KeyboardInterrupt:
            setattr(sys, 'app_terminated', True)
            print('^C')
            status = -100
    return status


if '__name__ == __main__':
    try:
        from optparse import OptionParser

        parser = OptionParser(usage=('Usage: %prog [options] <Device Address>\n\n' + SG_CAPTURE_VERINFO))
        parser.get_option("-h").help = "Show this help message and exit."
        parser.add_option("--version",
                          action="store_true", default=False, dest="show_version",
                          help="Show version.")
        parser.add_option("-c", "--channels",
                          action="store", type="int", default=6, dest="channels",
                          help='Audio channels, 1/8/9/16/17/...')
        parser.add_option("-d", "--duration",
                          action="store", type="float", default=SG_DEF_DURATION, dest="duration",
                          help='Duration in seconds, default is "{}"s.'.format(SG_DEF_DURATION))
        parser.add_option("--fp", "--file-path",
                          action="store", type="string", default='', dest="file_path",
                          help="Path of the output PCM file.")
        parser.add_option("--fw", "--add-fw-rule",
                          action="store_true", default=False, dest="add_fw_rule",
                          help='Add a firewall rule to the Windows Advanced Firewall.')
        parser.add_option("--la", "--listen-addr",
                          action="store", type="string", default='', dest="listen_addr",
                          help='Capture\'s listen address, format is "<IP address>", ":<port>" or "<IP '
                               'address>:<port>".')
        parser.add_option("--nt", "--no-timestamp",
                          action="store_true", default=False, dest="no_timestamp",
                          help='Build file name without timestamp.')
        parser.add_option("-p", "--password",
                          action="store", type="string", default=SG_DEF_PASSWORD, dest="password",
                          help='Device password, default is "{}".'.format(SG_DEF_PASSWORD))
        (options, args) = parser.parse_args()

        if options.show_version:
            print(SG_CAPTURE_VERINFO)
            sys.exit(0)

        if options.add_fw_rule:
            win_advfw_add_program_rule(sys.executable, force=True)
            sys.exit(0)

        if len(args) != 1:
            parser.print_help()
            sys.exit(1)

        status = sg_capture_main(args[0], options)
        sys.exit(status)
    except KeyboardInterrupt:
        print('^C')
        sys.exit(-100)
