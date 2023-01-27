from port_type import PortType


class ScanningInfo:
    def __init__(self, port_type: PortType, scanning_range: range):
        self._type = port_type
        self._range = scanning_range


class PortInfo:
    def __init__(self, port_type: PortType, port_num: int):
        self._type = port_type
        self._num = port_num


class AfterScanningInfo:
    def __init__(self, port_type: str, port: int, time: float):
        self._type = port_type
        self._port = port
        self._time = time

    def __hash__(self):
        return hash(self._type) + hash(self._port) + hash(self._time)

    def __eq__(self, other):
        return self._type == other._type and self._port == other._port

    def simple(self) -> str:
        return f'{self._type:<6} {self._port:<9}'

    def all(self) -> str:
        return f'{self._type:<6} {self._port:<9} {round(self._time,3)}ms'
