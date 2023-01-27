import socket
import threading
from port_scan_info import ScanningInfo, AfterScanningInfo, PortInfo
from port_type import PortType
import argparse
import time


class Scanner:
    def __init__(self, ip: str, timeout: int, candidates: list[ScanningInfo],
                 verbose: bool = False, thread_count: int = 10):
        self._ip = ip
        self._timeout = timeout
        self._candidates = candidates
        self._thread_count = thread_count
        self._verbose = verbose
        self._threads = []
        self._output = set()
        self._lock = threading.Lock()

    def __create_order(self) -> list[PortInfo]:
        _result = []
        for _c in self._candidates:
            for i in _c._range:
                _result.append(PortInfo(_c._type, i))

        return _result

    def __chunks(self, source: list):
        i = 0
        while i < len(source):
            yield source[i: i + self._thread_count]
            i += self._thread_count

    def scan(self):
        _order = self.__create_order()
        for chunk in self.__chunks(_order):
            _thread = threading.Thread(target=self.__scan_for_thread, args=([chunk]))
            self._threads.append(_thread)

        for _t in self._threads:
            _t.start()

        for _t in self._threads:
            _t.join()

        _label = f'{"Тип":<6} {"Номер":<9} {"Время":<6}' if self._verbose else f'{"Тип":<6} {"Номер":<9}'
        print(_label)
        for _info in self._output:
            print(_info.all() if self._verbose else _info.simple())

    def __scan_for_thread(self, infos: list[PortInfo]):
        for _info in infos:
            if _info._type == PortType.TCP:
                self.__tcp_connect(_info._num)
            else:
                self.__udp_connect(_info._num)

    def __socket_response(self, sock: socket.socket, port: int, port_type: PortType):
        _open = False
        _elapsed = 0

        try:
            _start = time.time()
            sock.connect((self._ip, port))
            _end = time.time()

            _open = True
            _elapsed = _end - _start
        except:
            _open = False

        if _open:
            while self._lock.locked():
                time.sleep(0.01)

            self._lock.acquire()
            try:
                self._output.add(AfterScanningInfo(port_type.name, port, round(_elapsed, 3)))
            finally:
                self._lock.release()

    def __udp_connect(self, port):
        _udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _udp_socket.settimeout(self._timeout)

        self.__socket_response(_udp_socket, port, PortType.UDP)

    def __tcp_connect(self, port):
        _tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _tcp_socket.settimeout(self._timeout)

        self.__socket_response(_tcp_socket, port, PortType.TCP)


def parse_ports(ports_raw: list) -> list[ScanningInfo]:
    _result = []
    for _arg in ports_raw:
        _type, _ranges = _arg.split('/')
        for _range_raw in _ranges.split(','):
            _start, _end = map(int, _range_raw.split('-'))

            if _type.lower() == 'tcp':
                _result.append(ScanningInfo(PortType.TCP, range(_start, _end + 1)))
            else:
                _result.append(ScanningInfo(PortType.UDP, range(_start, _end + 1)))

    return _result


if __name__ == "__main__":
    _parser = argparse.ArgumentParser()
    _parser.add_argument('ip_address', type=str)
    _parser.add_argument('ports', type=str, nargs='+')
    _parser.add_argument('-t', '--timeout', dest='timeout', type=float, default=2.0)
    _parser.add_argument('-v', '--verbose', dest='verbose', action='store_true')
    _parser.add_argument('-j', dest='threads_num', type=int, default=10)

    args = _parser.parse_args()
    _ports = parse_ports(args.ports)
    _scanner = Scanner(args.ip_address, args.timeout, _ports, args.verbose, args.threads_num)
    _scanner.scan()

