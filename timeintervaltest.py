from Localtest import LocalPclsc
from charm.toolbox.pairinggroup import *
import datetime
import pandas as pd


def main():
    curves = ["SS512", "BN254", "MNT201", "MNT224"]
    average_times = {}

    for curve in curves:
        global PP, pk_TA, sk_TA
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
        data = []
        for j in range(5, 8):
            for i in range(ex):
                ###### Initialization ######
                time_init_start = datetime.datetime.now().timestamp()
                PP, pk_TA, sk_TA = locals.Initialization(j, 10, 4)
                time_init_end = datetime.datetime.now().timestamp()
                time_init = time_init_end-time_init_start
                time_init_total += time_init

                ####  Registration   ######
                time_reg_start = datetime.datetime.now().timestamp()
                PIDS, SKR = locals.Registration(PP, RIDS, sk_TA)
                time_reg_end = datetime.datetime.now().timestamp()
                # print("Registration time: ", time_reg_end-time_reg_start, " seconds")
                time_reg = time_reg_end-time_reg_start
                time_reg_total += time_reg

                ####  Key Generation and Pseudonym Construction ####
                time_KAndPC_start = datetime.datetime.now().timestamp()
                PK_IDS, SK_IDS = locals.KAndPC(PP, RIDS, pk_TA, SKR)
                time_KAndPC_end = datetime.datetime.now().timestamp()
                # print("Key Generation and Pseudonym Construction time: ",
                #       time_KAndPC_end-time_KAndPC_start, " seconds")
                time_KAndPC = time_KAndPC_end-time_KAndPC_start
                time_KAndPC_total += time_KAndPC

                ####  Data Signcryption ####
                time_Sign_start = datetime.datetime.now().timestamp()
                ct_message, ct_key, sigma, timestamp = locals.DataSignCryption(
                    PIDS, PK_IDS, SK_IDS, 15)

                time_Sign_end = datetime.datetime.now().timestamp()
                # print("DataSignCryption time: ",
                #       time_Sign_end-time_Sign_start, " seconds")
                time_Sign = time_Sign_end-time_Sign_start
                time_Sign_total += time_Sign
                sk_current = SK_IDS['SK_fai']

                ####   Update  ####
                time_Update_start = datetime.datetime.now().timestamp()
                sk_current = locals.SkidUpdate(PP, sk_current, 15)
                time_Update_end = datetime.datetime.now().timestamp()
                # print("Update time: ",
                #       time_Update_end-time_Update_start, " seconds")
                time_Update = time_Update_end-time_Update_start
                time_Update_total += time_Update

                ####  Puncture ####
                time_Puncture_start = datetime.datetime.now().timestamp()
                for k in range(10):
                    sk_current = locals.SKIdPuncture(
                        PP, sk_current, puncture_tag_set[k])
                time_Puncture_end = datetime.datetime.now().timestamp()
                # print("Puncture time: ",
                #       time_Puncture_end-time_Puncture_start, " seconds")
                time_Puncture = time_Puncture_end-time_Puncture_start
                time_Puncture_total += time_Puncture

                #### Data Recovery ####
                time_Recovery_start = datetime.datetime.now().timestamp()
                original_data = locals.DataRecovery(
                    PIDS, ct_key, PK_IDS, sk_current, SK_IDS['a0'], sigma, ct_message, timestamp)
                time_Recovery_end = datetime.datetime.now().timestamp()
                # print("DataRecovery time: ",
                #       time_Recovery_end-time_Recovery_start, " seconds", "Decrypted Data:", original_data)
                time_Recovery = time_Recovery_end-time_Recovery_start
                time_Recovery_total += time_Recovery

                #### PseudonymUpdate ####
                time_PU_start = datetime.datetime.now().timestamp()
                locals.PseudonymUpdate(
                    PP, sk_TA, PIDS, RIDS)

                time_PU_end = datetime.datetime.now().timestamp()
                # print("PseudonymUpdate time: ",
                #       time_PU_end-time_PU_start, " seconds")
                time_PU = time_PU_end-time_PU_start
                time_PU_total += time_PU

                #### TracingAndRevocation ####
                time_Trace_start = datetime.datetime.now().timestamp()
                locals.TracingAndRevocation(
                    sk_TA, PIDS)

                time_Trace_end = datetime.datetime.now().timestamp()
                # print("TracingAndRevocation time: ",
                #       time_Trace_end-time_Trace_start, " seconds")
                time_Trace = time_Trace_end-time_Trace_start
                time_Trace_total += time_Trace

            average_time_init = time_init_total / ex
            average_time_reg = time_reg_total / ex
            average_time_KAndPC = time_KAndPC_total / ex
            average_time_Sign = time_Sign_total / ex
            average_time_Update = time_Update_total / ex
            average_time_Puncture = time_Puncture_total / ex
            average_time_Recovery = time_Recovery_total / ex
            average_time_PU = time_PU_total / ex
            average_time_Trace = time_Trace / ex
            average_times[j] = [j, average_time_init, average_time_reg, average_time_KAndPC, average_time_Sign,
                                average_time_Update, average_time_Puncture, average_time_Recovery, average_time_PU, average_time_Trace]

            data.append(average_times[j])

        data.insert(0, ["τ_max", "Initialization", "Registration", "KG&PC", "Signcryption",
                        "Recovery Key", "Puncture Key", "Update", "Pseudonym Update", "T&R"])
        df = pd.DataFrame(data)

        excel_file = curve + '.xlsx'
        df.to_excel(excel_file, index=False, header=False)

        print(f"Excel表格已保存到 {excel_file}")


if __name__ == '__main__':
    main()
