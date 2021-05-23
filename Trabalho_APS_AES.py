import base64
from copy import deepcopy
import random
# Tabelas
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

invSbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xBf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfB,
    0x7C, 0xe3, 0x39, 0x82, 0x9B, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xC4, 0xde, 0xe9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xa6, 0xC2, 0x23, 0x3d, 0xee, 0x4C, 0x95, 0x0B, 0x42, 0xfa, 0xC3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xB2, 0x76, 0x5B, 0xa2, 0x49, 0x6d, 0x8B, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5C, 0xCC, 0x5d, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xB9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xaB, 0x00, 0x8C, 0xBC, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xd0, 0x2C, 0x1e, 0x8f, 0xCa, 0x3f, 0x0f, 0x02, 0xC1, 0xaf, 0xBd, 0x03, 0x01, 0x13, 0x8a, 0x6B,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdC, 0xea, 0x97, 0xf2, 0xCf, 0xCe, 0xf0, 0xB4, 0xe6, 0x73,
    0x96, 0xaC, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1C, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xC5, 0x89, 0x6f, 0xB7, 0x62, 0x0e, 0xaa, 0x18, 0xBe, 0x1B,
    0xfC, 0x56, 0x3e, 0x4B, 0xC6, 0xd2, 0x79, 0x20, 0x9a, 0xdB, 0xC0, 0xfe, 0x78, 0xCd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xeC, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xB5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xC9, 0x9C, 0xef,
    0xa0, 0xe0, 0x3B, 0x4d, 0xae, 0x2a, 0xf5, 0xB0, 0xC8, 0xeB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7e, 0xBa, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7d
]


def encode64(text):
    temp = text.encode("u8")
    encode = base64.b64encode(temp)
    return encode.decode()


def decode64(text):
    text = text.encode("u8")
    decode = base64.decodebytes(text).decode()
    return decode

# Funcões Gerais
def HexToBin(hexa):
    return ((8 - len(bin(int(hexa, 16))[2:])) % 8) * '0' + bin(int(hexa, 16))[2:]


def BinPadding(binario):
    return ((8 - len(binario)) % 8) * '0' + binario


def HexPadding(hexa):
    return ((2 - len(hexa)) % 2) * '0' + hexa


def Xor8Bits(bit1, bit2):
    rest = ''
    for i in range(8):
        rest += str(int(bit1[i]) ^ int(bit2[i]))
    return rest


def XorAndPadAndTrasform(a, b):
    aNew = bin(a)[2:]
    bNew = bin(b)[2:]
    aNew = BinPadding(aNew)
    bNew = BinPadding(bNew)
    result = Xor8Bits(aNew, bNew)
    return int(result, 2)


def Cezar(texto, chave):
    result = []
    for i in range(len(texto)):
        result.append(hex(((int(texto[i], 16) + ord(chave[i]))) & 255)[2:])
    return result


def InvCezar(texto, chave):
    result = []
    for i in range(len(texto)):
        result.append(hex((((int(texto[i], 16) - ord(chave[i]))) & 255))[2:])
    return result

# Mix Columns
def MultPor2(entrada):
    result = entrada << 1  # Multiplicando por 10 ou movendo uma casa para esquerda e adicionando 1 zero a direita
    result &= 0xff  # Ele ignora o bit que estiver a esquerda (fora de 8 bits) e faz um xor invertido com o resto e o 0xff(255(1111 1111))
    if (entrada & 128) != 0:  # Ele verifica se o bit mais a esquerda da entrada é igual a 1, se for ele faz um xor com o 0x1b
        result = BinPadding(bin(result)[2:])
        result = Xor8Bits(result, '00011011')
    else:
        result = bin(result)[2:]
    return int(result, 2)


def MultPor3(entrada):
    # Pega a multiplicação da entrada por 2 e faz um xor com  ele mesmo, o que resulta na multiplicação da entrada por 3
    return int(Xor8Bits(BinPadding(bin(MultPor2(entrada))[2:]), BinPadding(bin(entrada)[2:])), 2)


def MatrizMult(entrada):
    #  Faz a Multplicação com a matriz e depois um Xor com os resultados  #
    r = [
        XorAndPadAndTrasform(MultPor2(entrada[0]), XorAndPadAndTrasform(MultPor3(entrada[1]), XorAndPadAndTrasform(entrada[2], entrada[3]))),
        XorAndPadAndTrasform(MultPor2(entrada[1]), XorAndPadAndTrasform(MultPor3(entrada[2]), XorAndPadAndTrasform(entrada[3], entrada[0]))),
        XorAndPadAndTrasform(MultPor2(entrada[2]), XorAndPadAndTrasform(MultPor3(entrada[3]), XorAndPadAndTrasform(entrada[0], entrada[1]))),
        XorAndPadAndTrasform(MultPor2(entrada[3]), XorAndPadAndTrasform(MultPor3(entrada[0]), XorAndPadAndTrasform(entrada[1], entrada[2]))),
    ]
    return r


def MixColumns(entrada):
    entradaMatriz = [entrada[i*4:(i+1)*4] for i in range(4)]
    result = [[] for i in range(4)]
    entraTrans = [[[]for i in range(4)]for z in range(4)]

    for linha in range(4):
        for coluna in range(4):
            entraTrans[linha][coluna] = int(entradaMatriz[linha][coluna], 16)
    #  Transforma a Matriz de entrada em colunas, depois faz as colunas serem multiplicadas  #
    #  pela matriz do Mix Colunms, com a multiplicação feita trasforma tudo em linha novamente  #
    for i in range(4):
        col = [entraTrans[z][i] for z in range(4)]
        col = MatrizMult(col)
        for z in range(4):
            result[z].append(col[z])

    for linha in range(4):
        for coluna in range(4):
            result[linha][coluna] = hex(result[linha][coluna])[2:]
    for i in range(4):
        result += result[0]
        del(result[0])
    return result

def InvMixColunms(entrada):
    result = MixColumns(entrada)
    result = MixColumns(result)
    result = MixColumns(result)
    return result


# Key Scredule
def RotWord(coluna):
    return coluna[1:] + coluna[0:1]


def padronizarChave(chave):

    chave = [hex(ord(letra))[2:] for letra in chave]

    while len(chave) != 16:  # Caso a chave seja menor que 16 bytes
        chave.append(hex(0)[2:])

    keyState = []
    for i in range(4):  # Cria as colunas da Key State
        keyState.append(chave[:4])
        del chave[:4]

    return keyState


def inverterChave(keyState):
    invKey = []
    for i in range(len(keyState)): # Inversão das "linhas" para "colunas"
        conj = []
        for j in range(len(keyState[i])):
            conj.append(keyState[j][i])
        invKey += conj
    return invKey


def KeySchedule(keyState):


    rcon = [[0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00],
            [0x1b, 0x00, 0x00, 0x00],
            [0x36, 0x00, 0x00, 0x00],
            ]

    rounds = 10
    chaves = []
    invKey = inverterChave(keyState)
    chaves.append(deepcopy(invKey))
    for rodada in range(rounds):
        for i in range(len(keyState)):
            if i == 0:
                rotWord = RotWord(keyState[-1])  # Rotword

                rotWord = SubBytes(rotWord)


                for j in range(len(keyState[i])):  # XOR entre Coluna 0, RotWord e Rcon
                    x = HexToBin(keyState[i][j])
                    y = HexToBin(rotWord[j])
                    z = HexToBin(str(hex(rcon[0][j])[2:]))

                    temp = Xor8Bits(x, y)

                    temp = Xor8Bits(temp, z)
                    temp = hex(int(temp, 2))[2:]



                    keyState[i][j] = temp
                rcon = RotWord(rcon)  # Rotaciona o Rcon para a progressao dos rounds

            else:
                for j in range(len(keyState[i])):
                    x = HexToBin(keyState[i][j])
                    y = HexToBin(keyState[i - 1][j])

                    temp = Xor8Bits(x, y)
                    temp = hex(int(temp, 2))[2:]

                    keyState[i][j] = temp
        invKey = inverterChave(keyState)

        chaves.append(deepcopy(invKey))

    return chaves


# Sub Bytes da lista State
def SubBytes(state):
    result = []
    for i in range(len(state)):
        hexa = hex(int(state[i], 16))
        newHexa = hex(sbox[int(hexa, 16)])[2:]
        result.append(HexPadding(newHexa))
    return result

def InvSubBytes(state):
    result = []
    for i in range(len(state)):
        hexa = hex(int(state[i], 16))
        newHexa = hex(invSbox[int(hexa, 16)])[2:]
        result.append(HexPadding(newHexa))
    return result

# Shift Row
def ShiftRow(state):
    # Matriz 4x4 com espaços vazios para apanhar na nova ordem
    matrizState = [['' for coluna in range(4)] for linha in range(4)]
    # Lista vazia para receber os hexadecimais já rotacionados
    result = []
    # Variável para ajudar a fazer referência dos índices da lista 'state'
    i = -1

    for linha in range(4):
        for coluna in range(4):
            i += 1
            # Lógica para rotacionar e incluir o elemento que se encaixa no intervalo
            matrizState[linha][coluna - linha] = state[i]
    for linha in range(4):
        for coluna in range(4):
            # Alimentação da lista 'result' com os dados da matriz 'matrizState'
            result.append(matrizState[linha][coluna])
    return result


def InvShiftRow(state):
    result = ShiftRow(state)
    result = ShiftRow(result)
    result = ShiftRow(result)
    return result

# Add Round Key
def AddRoundKey(state, key):
    # Lista que recebe o State com a chave já adicionada
    result = []
    for i in range(0, 16):
        # Variáveis que recebem os Hexa's convertidos para Binários
        byte1 = HexToBin(state[i])
        byte2 = HexToBin(key[i])
        # Variável que recebe o XOR bit por bit entre o 'byte1' e 'byte2'
        addKey = Xor8Bits(byte1, byte2)
        newKey = HexPadding(hex(int(addKey, 2))[2:])
        # Alimentação da lista 'result' com o resultado da variável 'addKey'
        result.append(newKey)
    return result


def EncriptAES(texto, chave):

    plainText = []
    subChaves = KeySchedule(padronizarChave(chave))
    plainCipher = ''

    for i in range(11):
        for y in range(16):
            subChaves[i][y] = HexPadding(subChaves[i][y])
    # Divide o texto de entrada em bloco de 16 caracteres #
    for i in range(len(texto) // 16 + 1 if len(texto) % 16 != 0 else len(texto) // 16):
        plainText.append(((16 - len(texto[i*16:(i+1)*16])) % 16) * chr(0) + texto[i*16:(i+1)*16])

    for conjunto in plainText:
        conj = []
        conj2 = [[] for i in range(4)]
        for i in range(16):
            conj.append(HexPadding(hex(ord(conjunto[i]))[2:])),
        for i in range(4):
            conj2[i] = conj[i*4:(i+1)*4]
        conj = inverterChave(conj2)

        aKey = AddRoundKey(conj, subChaves[0])

        for rounds in range(9):
            if rounds == 4:
                aKey = Cezar(aKey, chave)
            sBytes = SubBytes(aKey)
            sRow = ShiftRow(sBytes)
            mCol = MixColumns(sRow)
            aKey = AddRoundKey(mCol, subChaves[rounds+1])
        sBytes = SubBytes(aKey)
        sRow = ShiftRow(sBytes)
        aKey = AddRoundKey(sRow, subChaves[10])

        for i in range(16):
            aKey[i] = HexPadding(aKey[i])
            plainCipher += aKey[i]
    return encode64(plainCipher)


def DecriptAES(texto, chave):
    texto = decode64(texto)
    plainText = []
    subChaves = KeySchedule(padronizarChave(chave))
    plainCipher = ''

    for i in range(11):
        for y in range(16):
            subChaves[i][y] = HexPadding(subChaves[i][y])
    # Divide o texto de entrada em bloco de 16 caracteres #
    for i in range(len(texto) // 32 + 1 if len(texto) % 32 != 0 else len(texto) // 32):
        plainText.append(((32 - len(texto[i*32:(i+1)*32])) % 32) * '0' + texto[i*32:(i+1)*32])
    for conjunto in plainText:
        result = []
        matrizEntrada = []
        conj = []
        conj2 = [[] for i in range(4)]
        for i in range(16):
            matrizEntrada.append(conjunto[i*2:(i+1)*2])
        for i in range(4):
            conj2[i] = matrizEntrada[i*4:(i+1)*4]
            conj += conj2[i]

        addKey = AddRoundKey(conj, subChaves[10])
        invShifRow = InvShiftRow(addKey)
        invSubByte = InvSubBytes(invShifRow)
        for rodada in range(9):
            if rodada == 5:
                invSubByte = InvCezar(invSubByte, chave)
            addKey = AddRoundKey(invSubByte, subChaves[9-rodada])
            invMixCol = InvMixColunms(addKey)
            invShifRow = InvShiftRow(invMixCol)
            invSubByte = InvSubBytes(invShifRow)
        addKey = AddRoundKey(invSubByte, subChaves[0])
        for linha in range(4):
            for coluna in range(4):
                result.append(addKey[(coluna*4)+linha])
        for i in range(16):
            plainCipher += chr(int(result[i], 16))
        plainCipher = plainCipher.replace(chr(0), '')
    return plainCipher


if __name__ == '__main__':
    Msg = str(input('Digite sua mensagem: '))
    Chave = str(input('Digite a chave (16 caracteres): '))
    if len(Chave) == 16:
        Codificado = EncriptAES(Msg, Chave)
        Decodificado = DecriptAES(Codificado, Chave)
        print()
        print('Mensagem codificada:', Codificado)
        print('Mensagem decodificado:', Decodificado)
    else:
        print("Chave com tamanho incorreto. A chave comporta 16 caracteres")