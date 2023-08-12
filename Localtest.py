from charm.toolbox.pairinggroup import *
import datetime
from pclsc import BT, PCLSC
from CuckooFilter import CuckooFilter
import pyaes
from Crypto.Util.Padding import pad, unpad
import hashlib
import numpy as np


def Initialization(tao_max, n, k):
    global pclsc, group, PP, MSK, cuckoo_filter, ID_TA, R2P

    groupObj = PairingGroup('SS512')
    group = groupObj
    pclsc = PCLSC(groupObj)
    cuckoo_filter = CuckooFilter(size=1000)
    R2P = {}

    MSK, PP = pclsc.Setup(tao_max, n, k)
    # MSK, PP = pclsc.Setup(1048570, 20, 8)

    ID_TA = 'ta@mail.com'

    sk_par_TA = pclsc.PPKGen(PP, MSK, ID_TA)
    pk_TA, sk_TA = pclsc.FKGen(PP, sk_par_TA)

    return PP, pk_TA, sk_TA


def Registration(PP, RID, sk_TA):
    global ui, U_i
    ui = group.random(ZR)
    U_i = PP['g'] ** ui

    # timestamp = datetime.datetime.now().timestamp()
    uu = pclsc.H1(ID_TA, U_i,
                  U_i ** (sk_TA['sk']['beta'] + sk_TA['sk']['b']))

    uu_bytes = group.serialize(uu)
    RID_bytes = bytes(RID, 'utf-8')
    min_length = min(len(uu_bytes), len(RID_bytes))
    RID_bytes = RID_bytes[:min_length]
    uu_bytes = uu_bytes[:min_length]
    result_bytes = np.bitwise_xor(np.frombuffer(uu_bytes, dtype=np.uint8),
                                  np.frombuffer(RID_bytes, dtype=np.uint8))

    PID = {"PID1": U_i, "PID2": result_bytes}
    cuckoo_filter.insert(str(PID))
    SKR = pclsc.PPKGen(PP, MSK, str(PID))
    R2P[RID] = PID
    # print(SKR)

    return PID, SKR


def KAndPC(PP, RID, PK_TA, SKR):
    global gg, ID_TA, U_i
    ID_TA = 'ta@mail.com'

    Delta = pclsc.H1(ID_TA, PK_TA['A'], PP['SPK'])
    gg = (PK_TA["C"] * (PP['SPK'] ** Delta)) ** ui
    uu = pclsc.H1(ID_TA, U_i, gg)
    uu_bytes = group.serialize(uu)
    RID_bytes = bytes(RID, 'utf-8')
    min_length = min(len(uu_bytes), len(RID_bytes))
    RID_bytes = RID_bytes[:min_length]
    uu_bytes = uu_bytes[:min_length]
    PID2 = np.bitwise_xor(np.frombuffer(uu_bytes, dtype=np.uint8),
                          np.frombuffer(RID_bytes, dtype=np.uint8))

    PID = {"PID1": U_i, "PID2": PID2}
    hPid = pclsc.hid(str(PID))
    Delta_i = pclsc.H1(hPid, SKR['PSK']['A'], PP['SPK'])
    #  Delta = self.H1(hId, A, PP['SPK'])

    if (PP['g'] ** SKR['PSK']['b'] != SKR['PSK']['A'] * (PP['SPK'] ** Delta_i)):
        # g ** (a + delta * s)     g ** a *(g ** s *Delta_i) = g ** (a +  s * Delta_i)
        # U_i, timestamp = Registration(PP, RID, sk_TA)
        print("Re-Registration")
        return None, None
    else:
        beta = group.random(ZR)
        B = PP['g'] ** beta
        C = SKR['PSK']['A'] * B
        sk = {'beta': beta, 'b': SKR['PSK']['b']}
        PK_ID = {'A': SKR['PSK']['A'], 'C': C}
        SK_ID = {'a0': SKR['a0'], 'SK_fai': {
            'sk_tag': SKR['sk_tag'], 'sk_node': SKR['sk_node'], 'time_period': 0}, 'sk': sk}
        return PK_ID, SK_ID


def DataSignCryption(PIDS, PK_ID, SK_ID, tao):
    # key = secrets.token_bytes(32)
    key = group.random(GT)
    aes_key = hashlib.sha256(group.serialize(key)).digest()
    # print(aes_key)

    aes = pyaes.AESModeOfOperationECB(aes_key)
    data = b'Hello, Barron!'
    padded_data = pad(data, 16)

    ciphertext = aes.encrypt(padded_data)
    # aes = pyaes.AESModeOfOperationECB(aes_key)

    # decrypted_data = aes.decrypt(ciphertext)

    # original_data = unpad(decrypted_data, 16)

    # print("Decrypted Data:", original_data.decode('utf-8'))
    St = [None]*15

    for i in range(15):
        St[i] = 200+i

    ct, sigma, timestamp = pclsc.SignCrypt(
        PP,  St, tao, key, PK_ID, SK_ID, str(PIDS))

    return ciphertext, ct, sigma, timestamp


def DataRecovery(PIDS, ct_key, PK_IDS, sk_current, a0, sigma, ct_message, timestamp):
    if (cuckoo_filter.contains(str(PIDS))):
        C0_dot = pclsc.OCDeCrypt(PP, ct_key, sk_current)
        recover_key = pclsc.Unsigncrypt(
            PP, str(PIDS), PK_IDS, ct_key, C0_dot, a0, sigma, timestamp)
        aes_key = hashlib.sha256(group.serialize(recover_key)).digest()
        # print(aes_key)
        aes = pyaes.AESModeOfOperationECB(aes_key)
        decrypted_data = aes.decrypt(ct_message)
        original_data = unpad(decrypted_data, 16)
        return original_data

    else:
        return None


def SKIdPuncture(PP, SKR_current, tag):
    sk_new = pclsc.Puncture(PP, SKR_current, tag)
    return sk_new


def SkidUpdate(PP, sk_current, next_time_period):
    sk_current = pclsc.Update(PP, sk_current, next_time_period)
    return sk_current


def PseudonymUpdate(PP, PID, RID):
    ui_dot = group.random(ZR)
    U_i_dot = PP['g'] ** ui_dot

    # uu_dot = U_i_dot ^ gg
    # U_i_dot = uu_dot ^ PID['PID1']
    # uu_ba = pclsc.H1(ID_TA, U_i_dot, U_i_dot **
    #                  (sk_TA['sk']['beta'] + sk_TA['sk']['b']))
    # PID_2 = RID ^ uu_ba

    U_i_dot_bytes = group.serialize(U_i_dot)
    gg_bytes = group.serialize(gg)
    PID1_bytes = group.serialize(PID['PID1'])
    min_length = min(len(U_i_dot_bytes), len(gg_bytes), len(PID1_bytes))
    U_i_dot_bytes = U_i_dot_bytes[:min_length]
    gg_bytes = gg_bytes[:min_length]
    PID1_bytes = PID1_bytes[:min_length]
    U_i_dot = np.bitwise_xor(np.bitwise_xor(np.frombuffer(U_i_dot_bytes, dtype=np.uint8),
                                            np.frombuffer(gg_bytes, dtype=np.uint8)), np.frombuffer(PID1_bytes, dtype=np.uint8))
    uu_ba = pclsc.H1(ID_TA, U_i_dot, U_i_dot **
                     (sk_TA['sk']['beta'] + sk_TA['sk']['b']))

    uu_ba_bytes = group.serialize(uu_ba)
    RID_bytes = bytes(RID, 'utf-8')
    min_length = min(len(uu_ba_bytes), len(RID_bytes))
    RID_bytes = RID_bytes[:min_length]
    uu_ba_bytes = uu_ba_bytes[:min_length]
    PID_2 = np.bitwise_xor(np.frombuffer(uu_ba_bytes, dtype=np.uint8),
                           np.frombuffer(RID_bytes, dtype=np.uint8))

    PID_new = {"PID1": U_i_dot, "PID2": PID_2}
    cuckoo_filter.delete(str(PID))
    cuckoo_filter.insert(str(PID_new))


def TracingAndRevocation(PID):
    PID2 = PID['PID2']
    uuba_dot = pclsc.H1(
        ID_TA, PID['PID1'], PID['PID1'] ** (sk_TA['sk']['beta'] + sk_TA['sk']['b']))

    uuba_dot_bytes = group.serialize(uuba_dot)
    min_length = min(len(uuba_dot_bytes), len(PID2))
    uuba_dot_bytes = uuba_dot_bytes[:min_length]
    PID2 = PID2[:min_length]
    RID_bytes = np.bitwise_xor(np.frombuffer(
        uuba_dot_bytes, dtype=np.uint8), np.frombuffer(PID2, dtype=np.uint8))

    RID = str(RID_bytes, 'utf-8')
    R2P[RID] = PID
    cuckoo_filter.delete(str(PID))


def main():
    global PP, pk_TA, sk_TA, group, pclsc, ui, cuckoo_filter
    cuckoo_filter = CuckooFilter(size=1000)

    groupObj = PairingGroup('SS512')
    group = groupObj
    pclsc = PCLSC(groupObj)
    RIDS = "Peer_Bob"
    RIDR = "Peer_Alice"

    ###### Initialization ######
    time_init_start = datetime.datetime.now().timestamp()
    PP, pk_TA, sk_TA = Initialization(1048570, 20, 8)
    time_init_end = datetime.datetime.now().timestamp()
    print("Init time: ", time_init_end-time_init_start, " seconds")

    ####  Registration   ######
    time_reg_start = datetime.datetime.now().timestamp()
    PIDS, SKR = Registration(PP, RIDS, sk_TA)
    time_reg_end = datetime.datetime.now().timestamp()
    print("Registration time: ", time_reg_end-time_reg_start, " seconds")

    ####  Key Generation and Pseudonym Construction ####
    time_KAndPC_start = datetime.datetime.now().timestamp()
    PK_IDS, SK_IDS = KAndPC(PP, RIDS, pk_TA, SKR)

    time_KAndPC_end = datetime.datetime.now().timestamp()
    print("Key Generation and Pseudonym Construction time: ",
          time_KAndPC_end-time_KAndPC_start, " seconds")

    ####  Data Signcryption ####
    time_Sign_start = datetime.datetime.now().timestamp()
    ct_message, ct_key, sigma, timestamp = DataSignCryption(
        PIDS, PK_IDS, SK_IDS, 15)

    time_Sign_end = datetime.datetime.now().timestamp()
    print("DataSignCryption time: ",
          time_Sign_end-time_Sign_start, " seconds")

    sk_current = SK_IDS['SK_fai']

    ####   Update  ####
    time_Update_start = datetime.datetime.now().timestamp()
    sk_current = SkidUpdate(PP, sk_current, 15)
    time_Update_end = datetime.datetime.now().timestamp()
    print("Update time: ",
          time_Update_end-time_Update_start, " seconds")

    ####  Puncture ####
    time_Puncture_start = datetime.datetime.now().timestamp()
    puncture_tag_set = [None] * 100
    for i in range(100):
        puncture_tag_set[i] = i+10
    for k in range(100):
        sk_current = pclsc.Puncture(PP, sk_current, puncture_tag_set[k])
    time_Puncture_end = datetime.datetime.now().timestamp()
    print("Puncture time: ",
          time_Puncture_end-time_Puncture_start, " seconds")

    #### Data Recovery ####
    time_Recovery_start = datetime.datetime.now().timestamp()
    original_data = DataRecovery(
        PIDS, ct_key, PK_IDS, sk_current, SK_IDS['a0'], sigma, ct_message, timestamp)
    time_Recovery_end = datetime.datetime.now().timestamp()
    print("DataRecovery time: ",
          time_Recovery_end-time_Recovery_start, " seconds", "Decrypted Data:", original_data)

    #### PseudonymUpdate ####
    time_PU_start = datetime.datetime.now().timestamp()
    PseudonymUpdate(
        PP, PIDS, RIDS)

    time_PU_end = datetime.datetime.now().timestamp()
    print("PseudonymUpdate time: ",
          time_PU_end-time_PU_start, " seconds")

    #### TracingAndRevocation ####
    time_Trace_start = datetime.datetime.now().timestamp()
    TracingAndRevocation(
        PIDS)

    time_Trace_end = datetime.datetime.now().timestamp()
    print("TracingAndRevocation time: ",
          time_Trace_end-time_Trace_start, " seconds")


if __name__ == '__main__':
    main()
