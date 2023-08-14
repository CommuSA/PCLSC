from charm.toolbox.pairinggroup import *
import datetime
from pclsc import BT, PCLSC
from CuckooFilter import CuckooFilter
import pyaes
from Crypto.Util.Padding import pad, unpad
import hashlib
import numpy as np
import pandas as pd


class LocalPclsc:

    def __init__(self, groupObj):
        global group, pclsc
        group = groupObj
        pclsc = PCLSC(groupObj)

    def Initialization(self, tao_max, n, k):
        global pclsc, group, PP, MSK, cuckoo_filter, ID_TA, R2P

        groupObj = PairingGroup('SS512')
        group = groupObj
        pclsc = PCLSC(groupObj)
        cuckoo_filter = CuckooFilter(
            capacity=10000, bucket_size=4, fingerprint_size=8)
        R2P = {}

        MSK, PP = pclsc.Setup(tao_max, n, k)
        # MSK, PP = pclsc.Setup(1048570, 20, 8)

        ID_TA = 'ta@mail.com'

        sk_par_TA = pclsc.PPKGen(PP, MSK, ID_TA)
        pk_TA, sk_TA = pclsc.FKGen(PP, sk_par_TA)

        return PP, pk_TA, sk_TA

    def Registration(self, PP, RID, sk_TA):
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

    def KAndPC(self, PP, RID, PK_TA, SKR):
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

    def DataSignCryption(self, PIDS, PK_ID, SK_ID, tao):
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
        St = [None]*8

        for i in range(8):
            St[i] = 200+i

        ct, sigma, timestamp = pclsc.SignCrypt(
            PP,  St, tao, key, PK_ID, SK_ID, str(PIDS))

        return ciphertext, ct, sigma, timestamp

    def DataRecovery(self, PIDS, ct_key, PK_IDS, sk_current, a0, sigma, ct_message, timestamp):
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

    def SKIdPuncture(self, PP, SKR_current, tag):
        sk_new = pclsc.Puncture(PP, SKR_current, tag)
        return sk_new

    def SkidUpdate(self, PP, sk_current, next_time_period):
        sk_current = pclsc.Update(PP, sk_current, next_time_period)
        return sk_current

    def PseudonymUpdate(self, PP, sk_TA, PID, RID):
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

    def TracingAndRevocation(self, sk_TA, PID):
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
    curves = ["SS512", "BN254", "MNT201", "MNT224"]
    average_times = {}

    for curve in curves:
        global PP, pk_TA, sk_TA, group, pclsc, ui
        groupObj = PairingGroup(curve)
        locals = LocalPclsc(groupObj)
        RIDS = "Peer_Bob"
        RIDR = "Peer_Alice"
        puncture_tag_set = [None] * 10
        for i in range(10):
            puncture_tag_set[i] = i+10

        time_init_total = 0
        time_reg_total = 0
        time_KAndPC_total = 0
        time_Sign_total = 0
        time_Update_total = 0
        time_Puncture_total = 0
        time_Recovery_total = 0
        time_PU_total = 0
        time_Trace_total = 0

        ex = 2
        for i in range(ex):
            ###### Initialization ######
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            PP, pk_TA, sk_TA = locals.Initialization(10, 10, 4)
            groupObj.EndBenchmark()
            # print("Init time: ", time_init_end-time_init_start, " seconds")
            mdict = groupObj.GetGeneralBenchmarks()

            time_init_total = round(mdict['RealTime'] + time_init_total, 4)

            ####  Registration   ######
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            PIDS, SKR = locals.Registration(PP, RIDS, sk_TA)
            # print("Registration time: ", time_reg_end-time_reg_start, " seconds")
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_reg_total = round(mdict['RealTime'] + time_reg_total, 4)

            ####  Key Generation and Pseudonym Construction ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            PK_IDS, SK_IDS = locals.KAndPC(PP, RIDS, pk_TA, SKR)
            # print("Key Generation and Pseudonym Construction time: ",
            #       time_KAndPC_end-time_KAndPC_start, " seconds")
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_KAndPC_total = round(mdict['RealTime'] + time_KAndPC_total, 4)

            ####  Data Signcryption ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            ct_message, ct_key, sigma, timestamp = locals.DataSignCryption(
                PIDS, PK_IDS, SK_IDS, 15)
            # print("DataSignCryption time: ",
            #       time_Sign_end-time_Sign_start, " seconds")
            time_Sign_total = round(mdict['RealTime'] + time_Sign_total, 4)

            sk_current = SK_IDS['SK_fai']

            ####   Update  ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            sk_current = locals.SkidUpdate(PP, sk_current, 15)

            # print("Update time: ",
            #       time_Update_end-time_Update_start, " seconds")
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_Update_total = round(mdict['RealTime'] + time_Update_total, 4)

            ####  Puncture ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            for k in range(10):
                sk_current = locals.SKIdPuncture(
                    PP, sk_current, puncture_tag_set[k])
            # print("Puncture time: ",
            #       time_Puncture_end-time_Puncture_start, " seconds")
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_Puncture_total = round(
                mdict['RealTime'] + time_Puncture_total, 4)

            #### Data Recovery ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            original_data = locals.DataRecovery(
                PIDS, ct_key, PK_IDS, sk_current, SK_IDS['a0'], sigma, ct_message, timestamp)
            # print("DataRecovery time: ",
            #       time_Recovery_end-time_Recovery_start, " seconds", "Decrypted Data:", original_data)
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_Recovery_total = round(
                mdict['RealTime'] + time_Recovery_total, 4)

            #### PseudonymUpdate ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            locals.PseudonymUpdate(
                PP, sk_TA, PIDS, RIDS)
            # print("PseudonymUpdate time: ",
            #       time_PU_end-time_PU_start, " seconds")
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_PU_total = round(mdict['RealTime'] + time_init_total, 4)

            #### TracingAndRevocation ####
            groupObj.InitBenchmark()
            groupObj.StartBenchmark(
                ['RealTime'])
            locals.TracingAndRevocation(
                sk_TA, PIDS)

            # print("TracingAndRevocation time: ",
            #       time_Trace_end-time_Trace_start, " seconds")
            groupObj.EndBenchmark()
            mdict = groupObj.GetGeneralBenchmarks()
            time_Trace_total = round(mdict['RealTime'] + time_Trace_total, 4)

        average_time_init = time_init_total / ex
        average_time_reg = time_reg_total / ex
        average_time_KAndPC = time_KAndPC_total / ex
        average_time_Sign = time_Sign_total / ex
        average_time_Update = time_Update_total / ex
        average_time_Puncture = time_Puncture_total / ex
        average_time_Recovery = time_Recovery_total / ex
        average_time_PU = time_PU_total / ex
        average_time_Trace = time_Trace_total / ex
        average_times[curve] = [curve, average_time_init, average_time_reg, average_time_KAndPC, average_time_Sign,
                                average_time_Update, average_time_Puncture, average_time_Recovery, average_time_PU, average_time_Trace]

    data = [
        ["Curve", "Initialization", "Registration", "KG&PC", "Signcryption",
         "Recovery Key", "Puncture Key", "Update", "Pseudonym Update", "T&R"],
        average_times["SS512"], average_times["BN254"], average_times["MNT201"], average_times["MNT224"]
    ]

    df = pd.DataFrame(data)

    excel_file = 'output_benchmark.xlsx'
    df.to_excel(excel_file, index=False, header=False)

    print(f"Excel表格已保存到 {excel_file}")


if __name__ == '__main__':
    main()
