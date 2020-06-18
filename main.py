import os
import sys

from utils.reader import Reader
import json


class SCEDecode(Reader):
    def __init__(self, file_name: str, encrypted: bool = True):
        try:
            file_path = ('encrypted/' if encrypted else 'decrypted/') + file_name
            filedata = open(file_path, 'rb').read()
            decrypted = self.decrypt(filedata, 'secrets.')
            open(f'decrypted/{file_name}.decrypted.data', 'wb').write(decrypted)

            super().__init__(decrypted)
            items = []
            while len(decrypted) > 0:
                parsed, length = self.parse()
                if length == 0:
                    break
                items.append(parsed)

            output = json.dumps(items, indent=4)
            open(f'parsed/{file_name}.parsed.json', 'w').write(output)
        except Exception as e:
            print(e)

    def parse(self):
        length = self.readInteger()
        items = []
        i = 0
        while i < length / 2:
            items.append({
                'key': self.readString(),
                'value': self.readString()
            })
            i += 1
        return items, length

    def decrypt(self, data, key):
        result = b''
        c = 0
        while c < len(data):
            charCode = data[c] ^ ord(key[c % len(key)])
            result += charCode.to_bytes(1, 'big')
            c += 1
        return result


if __name__ == '__main__':
    if not os.path.exists('decrypted'):
        os.mkdir('decrypted')
    if not os.path.exists('parsed'):
        os.mkdir('parsed')
    if not os.path.exists('encrypted'):
        os.mkdir('encrypted')
        print('Put files into folder')
        sys.exit()
    # file_name = input('Type file name please: ')
    # sce = SCEDecode(file_name)
    
    sce = SCEDecode('log_current.sce')
    input('Type Enter to exit: ')
