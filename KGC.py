import datetime
from pclsc import BT, PCLSC
from charm.toolbox.pairinggroup import *
import argparse
import sys
import json
import aes

import multiaddr
import trio
from CuckooFilter import CuckooFilter

from libp2p import new_host
from libp2p.network.stream.net_stream_interface import INetStream
from libp2p.peer.peerinfo import info_from_p2p_addr
from libp2p.typing import TProtocol

PROTOCOL_ID = TProtocol("/chat/1.0.0")
MAX_READ_LEN = 2 ** 32 - 1


async def read_data(stream: INetStream) -> None:
    while True:
        read_bytes = await stream.read(MAX_READ_LEN)
        if read_bytes is not None:
            read_string = read_bytes.decode()
            if read_string != "\n":
                # Green console colour:     \x1b[32m
                # Reset console colour:     \x1b[0m
                if (read_string[:6] == "{\"Ui\":"):
                    global SKR
                    Peer_info = eval(read_string)
                    SKR = Registration(Peer_info, sk_TA)
                    print('success Registration')
                else:
                    print('error in Registration')

                print("\x1b[32m %s\x1b[0m " % read_string, end="")


async def write_data(stream: INetStream) -> None:
    async_f = trio.wrap_file(sys.stdin)

    while True:
        line = await async_f.readline()
        if (line == "1\n"):
            time = datetime.datetime.now().timestamp()
            egga = list(group.serialize(PP['egga']))
            g = list(group.serialize(PP['g']))
            g2 = list(group.serialize(PP['g2']))
            u0 = list(group.serialize(PP['u0']))
            u = list(group.serialize(PP['u']))
            h = list(group.serialize(PP['h']))
            SPK = list(group.serialize(PP['SPK']))
            maximum_tag_number = list(
                group.serialize(PP['maximum_tag_number']))
            v = list(group.serialize(PP['v']))
            n = list(group.serialize(PP['n']))
            l = list(group.serialize(PP['l']))

            PP_send = {'egga': egga, 'g': g, 'g2': g2, 'u0': u0, 'u': u, 'h': h, 'SPK': SPK,
                       'maximum_tag_number': maximum_tag_number, 'v': v, 'n': n, 'tree_depth': l}
            message = {'key': 'PP', 'value': PP_send}
            message_json = json.dumps(message)
            await stream.write(message_json.encode())

            # await stream.write(str({"PP": PP, "PK_TA": pk_TA}).encode())
            print(time)
        elif (line == "Registration_Feedback"):
            await stream.write(str(SKR).encode())
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
                f"python3 DOs.py "
                f"-p {int(port) + 1} "
                f"-d /ip4/{localhost_ip}/tcp/{port}/p2p/{host.get_id().pretty()} "
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


def Initialization(tao_max, n, k):
    global pclsc, group, PP, MSK, cuckoo_filter, ID_TA

    groupObj = PairingGroup('SS512')
    group = groupObj
    pclsc = PCLSC(groupObj)
    cuckoo_filter = CuckooFilter(size=1000)

    MSK, PP = pclsc.Setup(tao_max, n, k)
    # MSK, PP = pclsc.Setup(1048570, 20, 8)

    ID_TA = 'ta@mail.com'
    encrypt_tag_set = [None]*15

    for i in range(15):
        encrypt_tag_set[i] = 200+i

    puncture_tag_set = [None] * 100

    for i in range(100):
        puncture_tag_set[i] = i+10

    sk_par_TA = pclsc.PPKGen(PP, MSK, ID_TA)
    pk_TA, sk_TA = pclsc.FKGen(PP, sk_par_TA)

    return PP, pk_TA, sk_TA


def Registration(Peer_info, sk_TA):
    uu = pclsc.H1(ID_TA, Peer_info["Ui"],
                  Peer_info["Ui"] ** (sk_TA['sk']['beta'] + sk_TA['sk']['b']))
    PID = {"PID1": Peer_info["Ui"], "PID2": Peer_info["RID"] ^ uu}
    cuckoo_filter.insert(PID)
    SKR = pclsc.PPKGen(PP, MSK, str(PID))
    return SKR


def main() -> None:
    description = """
    This program demonstrates a simple p2p chat application using libp2p.
    To use it, first run 'python ./chat -p <PORT>', where <PORT> is the port number.
    Then, run another host with 'python ./chat -p <ANOTHER_PORT> -d <DESTINATION>',
    where <DESTINATION> is the multiaddress of the previous listener host.
    """
    global PP, pk_TA, sk_TA
    PP, pk_TA, sk_TA = Initialization(1048570, 20, 8)

    example_maddr = (
        "/ip4/127.0.0.1/tcp/8000/p2p/QmQn4SwGkDZKkUEptBRBvTmheQycxAHJUNmVEnjA2v1qe8Q"
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
