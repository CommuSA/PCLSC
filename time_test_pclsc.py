from charm.toolbox.pairinggroup import *
from charm.toolbox.secretutil import SecretUtil
import itertools
from charm.toolbox.hash_module import Waters
import math
import datetime
import pandas as pd

debug = False


class BT:
    def __init__(self, depth):
        global d
        d = depth

    @staticmethod
    def create():
        sbt = {}
        for i in range(2 ** d):
            s = bin(i)
            s2 = s[:2] + (d - len(s) + 2) * '0' + s[2:]
            btt = [None] * (s2.count('0'))
            l1 = list(s2)
            temp = 0
            for j in range(2, d + 2):
                if l1[j] == '0':
                    btt[temp] = s2[0:j] + '1'
                    temp += 1
            btt[-1] = s2
            sbt[i] = btt
        return sbt

    @staticmethod
    def find(bts, t1, t2):
        assert t1 < t2, 't1 must be less than t2'
        match = {}
        for i in bts[t2]:
            for j in bts[t1]:
                if j in i:
                    match[i] = j
                    continue
        return match


class PCLSC():
    @staticmethod
    def H1(k, P, Q):
        return group.hash((k, P, Q), ZR)

    @staticmethod
    def H2(m, id, P, c, tm):
        return group.hash((m, id, P, c, tm), ZR)

    @staticmethod
    def randomMessage():
        return group.random(GT)

    @staticmethod
    def hid(id):
        hidr = waters.hash(id)
        return hidr

    @staticmethod
    def remainder(value):
        return group.init(ZR, value)

    @staticmethod
    def W(f, bstr):  # bstr is a binary string
        term = f[0]
        for i in range(len(bstr) - 2):
            if bstr[i + 2] == '1':
                term *= f[i + 1]
        return term

    def __init__(self, groupObj, verbose=False):
        global util, group, waters
        group = groupObj
        util = SecretUtil(group, verbose)
        waters = Waters(group, 8, 32, 'sha256')

    # tree_depth是BT树的深度，|w|

    def Setup(self, tao, maximum_tag_number, k):
        global tree, bt, waters, l, bt
        # tao_max = tao

        sha2_byte_len = 32
        hLen = sha2_byte_len * 8
        bits = int(math.floor(hLen / k))
        log_t = tao
        l = int(log_t+1)
        tree = BT(l)
        bt = tree.create()

        waters = Waters(group, k, bits, 'sha256')

        g, g2 = group.random(G1), group.random(G2)
        alpha, s = group.random(ZR), group.random(ZR)

        uprime = group.random(G2)
        vector_u = [group.random() for _ in range(k)]
        egg = pair(g, g2)
        SPK = g ** s

        egga = egg ** alpha
        vector_v = [group.random(G2) for _ in range(l + 1)]  # type
        vector_h = [group.random(G2) for _ in range(maximum_tag_number)]
        MSK = {'g_alpha': g2 ** alpha, 's': s}  # master secret
        PP = {'egga': egga, 'g': g, 'g2': g2, 'u0': uprime, 'u': vector_u, 'h': vector_h, 'SPK': SPK,
              'maximum_tag_number': maximum_tag_number, 'v': vector_v, 'n': k, 'tree_depth': l}
        return MSK, PP

    def PPKGen(self, PP, MSK, ID):
        hId = self.hid(ID)
        t0 = self.remainder(0)
        rid, r0, r0_dot, a0 = group.random(ZR), group.random(
            ZR), group.random(ZR), group.random(ZR)
        sk_node_set = {}
        sk_tag = {}
        for eta in bt[0]:
            # delta_eta = group.random(ZR)
            sk_node_set[eta] = {}
            temp = PP['u0']
            for i in range(PP['n']):
                temp *= PP['u'][i] ** hId[i]
            sk_node_set[eta]['0'] = (MSK['g_alpha']**(1/a0)) * \
                (temp ** rid) * (PP['h'][0] ** r0) * \
                (self.W(PP['v'], eta)) ** r0_dot
            sk_node_set[eta]['1'] = PP['g'] ** r0_dot
            for j in range(len(eta) - 1, PP['tree_depth'] + 1):
                sk_node_set[eta][str(j)] = PP['v'][j] ** r0_dot
        k_emptyset = [(PP['h'][0] ** (-t0 ** i) * PP['h'][i]) **
                      r0 for i in range(1, PP['maximum_tag_number'])]
        sk_tag[str(0)] = {'1': PP['g'] ** r0, '2': PP['g']
                          ** rid, '3': t0, '4': k_emptyset, 'counter': 0}
        a = rid + r0 + r0_dot + a0
        A = PP['g'] ** a
        Delta = self.H1(hId, A, PP['SPK'])
        b = a + Delta * MSK['s']
        PSK = {'b': b, 'A': A}
        # sk0 = {'sk_tag': sk_tag, 'sk_node': sk_node_set, 'time_period': 0}
        SK_PAR = {'a0': a0, 'sk_tag': sk_tag,
                  'sk_node': sk_node_set, 'PSK': PSK}

        return SK_PAR

    # FKGen(PP,SK_par,ID): The Full Key Generation
    # algorithm is run by each entity to generate
    # their public and private key pairs. Given PP,
    # ID, and P SK as inputs, it outputs the public
    # and private key pair {PKID,SKID}, where SKID = {a0,SK0,φ,sk}.

    def FKGen(self, PP, SK_PAR):
        beta = group.random(ZR)
        B = PP['g'] ** beta
        C = SK_PAR['PSK']['A'] * B
        sk = {'beta': beta, 'b': SK_PAR['PSK']['b']}
        PK_ID = {'A': SK_PAR['PSK']['A'], 'C': C}
        SK_ID = {'a0': SK_PAR['a0'], 'SK_fai': {
            'sk_tag': SK_PAR['sk_tag'], 'sk_node': SK_PAR['sk_node'], 'time_period': 0}, 'sk': sk}
        return PK_ID, SK_ID


# sk_tag --> skφ
# sk_node_set --> sk0,η

    def SignCrypt(self, PP, tag_set, time_period, message, PK_IDS, SK_IDS, IDS):
        tag_number = len(tag_set)
        timestamp = datetime.datetime.now().timestamp()

        assert tag_number < PP['maximum_tag_number'], "加密标签数目大于系统最大数目"
        new_tag_set = [None] * tag_number
        hIDS = self.hid(IDS)
        # hIDR = waters.hash(IDR)
        for i in range(len(tag_set)):
            new_tag_set[i] = -self.remainder(tag_set[i])
        coefficients = [None] * PP['maximum_tag_number']
        for i in range(0, tag_number+1):
            temp2 = self.remainder(0)
            for j in itertools.combinations(new_tag_set, i):
                temp1 = self.remainder(1)
                for k in range(len(j)):
                    temp1 *= j[k]
                temp2 += temp1
            coefficients[tag_number-i] = temp2
        for i in range(tag_number+1, PP['maximum_tag_number']):
            coefficients[i] = self.remainder(0)
        z = group.random(ZR)
        c0 = message * PP['egga']**z
        c1 = PP['g'] ** z
        temp_c2 = PP['u0']
        for i in range(PP['n']):
            temp_c2 *= PP['u'][i] ** hIDS[i]
        c2 = temp_c2 ** z
        temp_c4 = group.init(G2, 1)
        for i in range(PP['maximum_tag_number']):
            temp_c4 *= PP['h'][i] ** coefficients[i]
        c4 = temp_c4 ** z
        c3 = (self.W(PP['v'], bt[time_period][-1])) ** z
        ct = {'c0': c0, 'c1': c1, 'c2': c2, 'c3': c3, 'c4': c4, 'tag_set': tag_set,
              'time_period': time_period, 'coefficients': coefficients}
        xita = self.H2(message, hIDS, PK_IDS, c1, timestamp)
        sigma = z + xita * (SK_IDS['sk']['beta']+SK_IDS['sk']['b'])
        return ct, sigma, timestamp

    def Puncture(self, PP, sk_current, tag):
        ri, ri_dot, lamdai = group.random(
            ZR), group.random(ZR), group.random(ZR)
        sk_node_set = {}
        for eta in bt[sk_current['time_period']]:
            sk_node_set[eta] = {}
            sk_node_set[eta]['0'] = sk_current['sk_node'][eta]['0'] * \
                PP['g2'] ** (-lamdai) * PP['h'][0] ** ri_dot
            sk_node_set[eta]['1'] = sk_current['sk_node'][eta]['1']
            for j in range(len(eta) - 1, PP['tree_depth'] + 1):
                sk_node_set[eta][str(j)] = sk_current['sk_node'][eta][str(j)]
        sk_tag = {}
        for item in sk_current['sk_tag']:
            sk_tag[item] = sk_current['sk_tag'][item]
        sk_tag[str(0)]['1'] *= PP['g'] ** ri_dot
        sk_tag[str(0)]['4'] = [(sk_tag[str(0)]['4'][i-1] * (PP['h'][0] ** (-self.remainder(sk_tag[str(0)]
                                                                                           ['3']) ** i) * PP['h'][i]) ** ri_dot) for i in range(1, PP['maximum_tag_number'])]
        sk_tag[str(tag)] = {'1': PP['g2'] ** lamdai * PP['h'][0] ** ri, '2': PP['g'] ** ri, '3': tag,
                            '4': [((PP['h'][0] ** (-self.remainder(tag) ** i) * PP['h'][i]) ** ri) for i in range(1, PP['maximum_tag_number'])],
                            'counter': len(sk_current['sk_tag'])}
        sk_new = {'sk_tag': sk_tag, 'sk_node': sk_node_set,
                  'time_period': sk_current['time_period']}
        return sk_new

    def Update(self, PP, sk_current, next_time_period):
        prefix = tree.find(bt, sk_current['time_period'], next_time_period)
        sk_node_set = {}
        r_dot = group.random(ZR)
        for eta in bt[next_time_period]:
            # delta_eta = group.random(ZR)
            temp = group.init(G2, 1)
            for j in range(len(prefix[eta]) - 1, len(eta) - 1):
                if eta[j + 1] == '1':
                    temp *= sk_current['sk_node'][prefix[eta]][str(j)]
            sk_node_set[eta] = {}
            sk_node_set[eta]['0'] = sk_current['sk_node'][prefix[eta]
                                                          ]['0'] * temp * (self.W(PP['v'], eta)) ** r_dot
            sk_node_set[eta]['1'] = sk_current['sk_node'][prefix[eta]
                                                          ]['1'] * PP['g'] ** r_dot
            for j in range(len(eta) - 1, PP['tree_depth'] + 1):
                sk_node_set[eta][str(j)] = sk_current['sk_node'][prefix[eta]][str(
                    j)] * PP['v'][j] ** r_dot
        sk_current['sk_node'] = sk_node_set
        sk_current['time_period'] = next_time_period
        return sk_current

    def OCDeCrypt(self, PP, ct, sk_current):
        punc_number = len(sk_current['sk_tag'])
        k = [group.init(G2, 1)] * punc_number
        for item in sk_current['sk_tag']:
            if item == '0':
                for l in range(PP['maximum_tag_number']-1):
                    k[sk_current['sk_tag'][item]['counter']
                      ] *= sk_current['sk_tag'][item]['4'][l] ** ct['coefficients'][l+1]
            else:
                for l in range(PP['maximum_tag_number']-1):
                    k[sk_current['sk_tag'][item]['counter']
                      ] *= sk_current['sk_tag'][item]['4'][l] ** ct['coefficients'][l+1]
        polynomial_value = [None] * punc_number
        for item in sk_current['sk_tag']:
            temp = group.init(ZR, 1)
            if item == '0':
                for j in range(len(ct['tag_set'])):
                    temp *= (self.remainder(sk_current['sk_tag'][item]
                             ['3']) - self.remainder(ct['tag_set'][j]))
                polynomial_value[0] = -1/temp
            else:
                for j in range(len(ct['tag_set'])):
                    temp *= (self.remainder(sk_current['sk_tag'][item]
                             ['3']) - self.remainder(ct['tag_set'][j]))
                polynomial_value[sk_current['sk_tag']
                                 [item]['counter']] = -1/temp
        Z = [None] * punc_number
        temp1 = (pair(ct['c1'], k[0])/pair(sk_current['sk_tag']
                 [str(0)]['1'], ct['c4'])) ** polynomial_value[0]
        temp2 = pair(sk_current['sk_tag'][str(0)]['2'], ct['c2']) * pair(sk_current['sk_node'][bt[sk_current['time_period']]
                                                                                               [-1]]['1'], ct['c3'])/pair(ct['c1'], sk_current['sk_node'][bt[sk_current['time_period']][-1]]['0'])
        Z[0] = temp1 * temp2
        for item in sk_current['sk_tag']:
            if item != str(0):
                Z[sk_current['sk_tag'][item]['counter']] = (pair(ct['c1'], k[sk_current['sk_tag'][item]['counter']])/pair(
                    sk_current['sk_tag'][item]['2'], ct['c4'])) ** polynomial_value[sk_current['sk_tag'][item]['counter']] / pair(ct['c1'], sk_current['sk_tag'][item]['1'])
        C0_dot = 1
        for i in range(len(Z)):
            C0_dot *= Z[i]
        return C0_dot

   # def Unsigncrypt(self, PP, IDS, PK_IDS, SK_IDR, ct, C0_dot, sigma, time_period):
    def Unsigncrypt(self, PP, IDS, PK_IDS, ct, C0_dot, a0, sigma, timestamp):
        recover_message = ct['c0'] * (C0_dot ** a0)
        hIdS = waters.hash(IDS)

        Xita_dot = self.H2(recover_message, hIdS,
                           PK_IDS, ct['c1'], timestamp)
        Delta_dot = self.H1(hIdS, PK_IDS['A'], PP['SPK'])
        left = PP['g'] ** sigma
        right = ct['c1'] * (PK_IDS['C'] ** Xita_dot) * \
            (PP['SPK'] ** (Xita_dot * Delta_dot))

        if left == right:
            print("successfully unsign")
            return recover_message
        else:
            print("failed")
            return recover_message


def main():
    # curves = ["SS512", "BN254", "MNT201", "MNT224"]
    curves = ["SS512"]
    average_times = {}
    for curve in curves:
        groupObj = PairingGroup(curve)

        pclsc = PCLSC(groupObj)

        message = group.random(GT)

        time_Setup_total = 0
        time_PPKGen_total = 0
        time_FKGen_total = 0
        time_SignCrypt_total = 0
        time_Update_total = 0
        time_Puncture_total = 0
        time_OCDeCrypt_total = 0
        time_Unsigncrypt_total = 0
        IDS = "bob@mail.com"
        IDR = "alice@mail.com"

        encrypt_tag_set = [None]*8

        for i in range(8):
            encrypt_tag_set[i] = 200+i

        puncture_tag_set = [None] * 10

        for i in range(10):
            puncture_tag_set[i] = i+10

        ex = 5
        data = []
        for j in range(15, 21):
            print(j)
            for i in range(ex):
                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                MSK, PP = pclsc.Setup(j, 10, 4)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_Setup_total = round(
                    mdict['RealTime'] + time_Setup_total, 6)

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                sk_current_par_S = pclsc.PPKGen(PP, MSK, IDS)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_PPKGen_total = round(
                    mdict['RealTime'] + time_PPKGen_total, 6)

                sk_current_par_R = pclsc.PPKGen(PP, MSK, IDR)

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                pk_S, sk_S = pclsc.FKGen(PP, sk_current_par_S)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_FKGen_total = round(
                    mdict['RealTime'] + time_FKGen_total, 6)

                pk_R, sk_R = pclsc.FKGen(PP, sk_current_par_R)

                sk_current = sk_S['SK_fai']
                a0 = sk_S['a0']

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                ct, sigma, timestamp = pclsc.SignCrypt(
                    PP, encrypt_tag_set, 15, message, pk_S, sk_S, IDS)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_SignCrypt_total = round(
                    mdict['RealTime'] + time_SignCrypt_total, 6)

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                sk_current = pclsc.Update(PP, sk_current, 15)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_Update_total = round(
                    mdict['RealTime'] + time_Update_total, 6)

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                for k in range(10):
                    sk_current = pclsc.Puncture(
                        PP, sk_current, puncture_tag_set[k])
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_Puncture_total = round(
                    mdict['RealTime'] + time_Puncture_total, 6)

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                C0_dot = pclsc.OCDeCrypt(PP, ct, sk_current)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_OCDeCrypt_total = round(
                    mdict['RealTime'] + time_OCDeCrypt_total, 6)

                groupObj.InitBenchmark()
                groupObj.StartBenchmark(
                    ['RealTime'])
                orig_m = pclsc.Unsigncrypt(
                    PP, IDS, pk_S, ct, C0_dot, a0, sigma, timestamp)
                groupObj.EndBenchmark()
                mdict = groupObj.GetGeneralBenchmarks()
                time_Unsigncrypt_total = round(
                    mdict['RealTime'] + time_Unsigncrypt_total, 6)

                print(message == orig_m)

            average_time_Setup = time_Setup_total / ex
            average_time_PPKGen = time_PPKGen_total / ex
            average_time_FKGen = time_FKGen_total / ex
            average_time_SignCrypt = time_SignCrypt_total / ex
            average_time_Update = time_Update_total / ex
            average_time_Puncture = time_Puncture_total / ex
            average_time_OCDeCrypt = time_OCDeCrypt_total / ex
            average_time_Unsigncrypt = time_Unsigncrypt_total / ex
            average_times[j] = [j, average_time_Setup, average_time_PPKGen, average_time_FKGen, average_time_SignCrypt,
                                average_time_Update, average_time_Puncture, average_time_OCDeCrypt, average_time_Unsigncrypt]
            data.append(average_times[j])
        data.insert(0,
                    ["τ_max", "Setup", "PPKGen", "FKGen", "Signcryption",
                     "Update", "Puncture", "OCDeCrypt", "Unsigncrypt"])

        df = pd.DataFrame(data)

        excel_file = curve + 'τ_test_PCLSC.xlsx'
        df.to_excel(excel_file, index=False, header=False)

        print(f"Excel表格已保存到 {excel_file}")


if __name__ == '__main__':
    main()
