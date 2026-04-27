"""
Minimal Modbus TCP server for OT simulation.
Listens on port 502 and responds to standard Modbus requests.
"""
import logging
from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSlaveContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)

logging.basicConfig(level=logging.WARNING)

store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [1] * 100),
    co=ModbusSequentialDataBlock(0, [1] * 100),
    hr=ModbusSequentialDataBlock(0, [0] * 100),
    ir=ModbusSequentialDataBlock(0, [0] * 100),
)
context = ModbusServerContext(slaves=store, single=True)

print("[*] Modbus TCP server listening on 0.0.0.0:502")
StartTcpServer(context, address=("0.0.0.0", 502))
