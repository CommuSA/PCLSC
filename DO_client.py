from charm.toolbox.pairinggroup import *
import datetime
from pclsc import BT, PCLSC
import aes
import os
import argparse
import sys
import json
from CuckooFilter import CuckooFilter

import multiaddr
import trio

from libp2p import new_host
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.typing import TProtocol

PROTOCOL_ID = TProtocol("/chat/1.0.0")
MAX_READ_LEN = 2 ** 32 - 1


def Registration(g):
    global ui
    ui = group.random(ZR)
    U_i = g ** ui
    timestamp = datetime.datetime.now().timestamp()
    return U_i, timestamp


def KAndPC(g, PK_TA, SKR, PP):
    global PID
    ID_TA = 'ta@mail.com'

    PID1 = U_i
    Delta = pclsc.H1(ID_TA, PK_TA["A"], PP['SPK'])
    gg = (PK_TA["C"] * (PP['SPK'] ** Delta)) ** ui
    uu = pclsc.H1(ID_TA, U_i, gg)
    PID2 = RID ^ uu
    PID = {"PID1": PID1, "PID2": PID2}
    Delta_i = pclsc.H1(str(PID), SKR['PSK']["A"], PP['SPK'])
    if (g ** SKR['PSK']['b'] != SKR['PSK']["A"] * (PP['SPK'] ** Delta_i)):
        U_i, timestamp = Registration(g)
        print("Re-Registration", timestamp)
    else:
        beta = group.random(ZR)
        B = PP['g'] ** beta
        C = SKR['PSK']['A'] * B
        sk = {'beta': beta, 'b': SKR['PSK']['b']}
        PK_ID = {'A': SKR['PSK']['A'], 'C': C}
        SK_ID = {'a0': SKR['a0'], 'SK_fai': {
            'sk_tag': SKR['sk_tag'], 'sk_node': SKR['sk_node'], 'time_period': 0}, 'sk': sk}
        return PK_ID, SK_ID


def DataSignCryption(PIDS, SK_ID, PIDR, tao):
    K = os.urandom(16)
    iv = os.urandom(16)

    encrypted = aes.AES(K).encrypt_ctr(b'Hello,Barron', iv)
    # print(aes.AES(key).decrypt_ctr(encrypted, iv))
    St = [None]*15

    for i in range(15):
        St[i] = 200+i

    ct, sigma, timestamp = pclsc.SignCrypt(PP, PIDS, SK_ID, PIDR, St, K, tao)
    return ct, sigma, timestamp


def DataRecovery(PIDS, ct, PK_IDS, sk_current, a0, sigma, encrypted, iv):
    cuckoo_filter.contains(PIDS)
    C0_dot = pclsc.OCDeCrypt(PP, ct, sk_current)
    recover_key = pclsc.Unsigncrypt(
        PP, PIDS, PK_IDS, ct, C0_dot, a0, sigma, timestamp)
    print(aes.AES(recover_key).decrypt_ctr(encrypted, iv))


async def read_data(stream: INetStream) -> None:
    global PP, PK_TA, SKR_i
    while True:
        read_bytes = await stream.read(MAX_READ_LEN)
        if read_bytes is not None:
            read_string = read_bytes.decode()
            received_data = json.loads(read_string)
            print(received_data)
            if received_data != "\n":
                # Green console colour:     \x1b[32m
                # Reset console colour:     \x1b[0m
                # read_string_de = group.deserialize(read_bytes)
                if (received_data['key'] == 'PP'):
                    print(received_data['value'])

                    PP = group.deserialize(bytes(received_data['value']))
                    print(g)
                    # PPATA = eval(read_string)
                    # PP = PPATA["PP"]
                    # PK_TA = PPATA["PK_TA"]
                    # print(PP['g'], type(PP['g']))
                elif (read_string[:7] == "{\""):
                    SKR_i = eval(read_string)
                else:
                    print('error in send PP', type(read_string))
            else:
                print('error in send PP', type(received_data))


async def write_data(stream: INetStream) -> None:
    global U_i, timestamp
    async_f = trio.wrap_file(sys.stdin)
    while True:
        line = await async_f.readline()
        if (line == "Registration\n"):

            U_i, timestamp = Registration(PP['g'])
            Peer_info = {"Ui": U_i, "RID": RID, "Timestamp": timestamp}
            await stream.write(str(Peer_info).encode())
        else:
            await stream.write(line.encode())


async def run(port: int, destination: str) -> None:
    localhost_ip = "127.0.0.1"
    listen_addr = multiaddr.Multiaddr(f"/ip4/0.0.0.0/tcp/{port}")
    host = new_host()
    async with host.run(listen_addrs=[listen_addr]), trio.open_nursery() as nursery:
        if not destination:  # its the server

            async def stream_handler(stream: INetStream) -> None:
                nursery.start_soon(read_data, stream)
                nursery.start_soon(write_data, stream)

            host.set_stream_handler(PROTOCOL_ID, stream_handler)

            print(
                f"Run 'python ./examples/chat/chat.py "
                f"-p {int(port) + 1} "
                f"-d /ip4/{localhost_ip}/tcp/{port}/p2p/{host.get_id().pretty()}' "
                "on another console."
            )
            print("Waiting for incoming connection...")

        else:  # its the client
            maddr = multiaddr.Multiaddr(destination)
            info = info_from_p2p_addr(maddr)
            # Associate the peer with local ip address
            await host.connect(info)
            # Start a stream with the destination.
            # Multiaddress of the destination peer is fetched from the peerstore using 'peerId'.
            stream = await host.new_stream(info.peer_id, [PROTOCOL_ID])

            nursery.start_soon(read_data, stream)
            nursery.start_soon(write_data, stream)
            print(f"Connected to peer {info.addrs[0]}")

        await trio.sleep_forever()


def main() -> None:
    global PP, RID
    RID = "Peer_Bob"
    global group, pclsc, ui, cuckoo_filter
    cuckoo_filter = CuckooFilter(size=1000)

    groupObj = PairingGroup('SS512')
    group = groupObj
    pclsc = PCLSC(groupObj)

    description = """
    This program demonstrates a simple p2p chat application using libp2p.
    To use it, first run 'python ./chat -p <PORT>', where <PORT> is the port number.
    Then, run another host with 'python ./chat -p <ANOTHER_PORT> -d <DESTINATION>',
    where <DESTINATION> is the multiaddress of the previous listener host.
    """
    example_maddr = (
        "/ip4/127.0.0.1/tcp/8000/p2p/QmQn4SwGkDZKkUEpBRBvTmheQycxAHJUNmVEnjA2v1qe8Q"
    )
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "-p", "--port", default=8000, type=int, help="source port number"
    )
    parser.add_argument(
        "-d",
        "--destination",
        type=str,
        help=f"destination multiaddr string, e.g. {example_maddr}",
    )
    args = parser.parse_args()

    if not args.port:
        raise RuntimeError("was not able to determine a local port")

    try:
        trio.run(run, *(args.port, args.destination))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
