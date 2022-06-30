import os
import shutil
import sys
import zlib
import struct
import pefile
import tinyaes

from utilities import *
from io import StringIO
from shutil import copyfile
from signal import signal, SIGINT
from configparser import ConfigParser


class PyInstaller(BinaryHandler):
    def __init__(self, path, output_dir):
        super(PyInstaller, self).__init__(path, output_dir)
        self.py_inst_archive = PyInstArchive(self.file_path)
        self.open_executable()
        self.close()
        self.py_inst_archive.open()

    def magic_recogniser(self):
        return self.py_inst_archive.checkFile()

    def __get_encryption_key(self, encrypted_key_path):
        try:
            encrypted_pyc = encrypted_key_path + ".pyc"
            copyfile(encrypted_key_path, encrypted_pyc)
            if os.path.exists(encrypted_pyc):
                encrypted_py = encrypted_key_path + ".py"
                decompile_pyc(encrypted_pyc, encrypted_py)
                ini_str = StringIO(
                    u"[secret]\n" + open(encrypted_py, 'r').read())
                config = ConfigParser()
                config.read_file(ini_str)
                temp_key = config.get("secret", "key")

                encryption_key = temp_key[1:len(temp_key) - 1]
                return encryption_key
            return None
        except Exception as e:
            printErr('An error occured while trying to get the encryption key.')
            printErrStack(e)

        finally:
            if os.path.exists(encrypted_pyc):
                os.remove(encrypted_pyc)
            if os.path.exists(encrypted_py):
                os.remove(encrypted_py)

    def __decrypt_pyc(self, extracted_binary_path, encryption_key):
        """
        - If executable is AES encrypted using pyinstallers --key arg, it will proceed to decrypt it:

            >>> _file.pyc.encrypted is encrypted! Proceeding with decryption. . .
        """
        crypt_block_size = 16
        encrypted_pyc_folder = os.path.join(
            extracted_binary_path, "PYZ-00.pyz_extracted")
        for _dir, subdir, files in os.walk(encrypted_pyc_folder):
            for _file in files:
                encrypted_pyc = os.path.join(encrypted_pyc_folder, _file)
                if os.path.exists(encrypted_pyc) and encrypted_pyc.endswith('.pyc.encrypted') and ('.pyc.encrypted.pyc' and '.pyc.encrypted.py') not in _file:
                    try:
                        # decrypt encrypted file
                        with open(encrypted_pyc, 'rb') as f:
                            data = f.read()
                        cipher = tinyaes.AES(
                            encryption_key.encode(), data[:crypt_block_size])
                        decrypt = cipher.CTR_xcrypt_buffer(
                            data[crypt_block_size:])
                        plaintext = zlib.decompress(decrypt)

                        with open(encrypted_pyc + ".pyc", 'wb') as decrypted_pyc_file:
                            # write pyc header
                            decrypted_pyc_file.write(
                                b'\x03\xf3\x0d\x0a\0\0\0\0')
                            # write bytecode
                            decrypted_pyc_file.write(plaintext)
                        printInfo(
                            f'{_file} is encrypted! Proceeding with decryption. . .')
                    except Exception as e:
                        printErr(
                            f'Error occured while decrypting {_file}')
                        printErrStack(e)
                    finally:
                        os.remove(encrypted_pyc)

    # Check if pyinstaller executable is encrypted using "--key" arg

    def __decrypt(self):
        encrypted_key_path = os.path.join(
            os.getcwd(), 'pyimod00_crypto_key.pyc')
        if os.path.exists(encrypted_key_path):
            encryption_key = self.__get_encryption_key(encrypted_key_path)
            if encryption_key is not None:
                self.__decrypt_pyc(os.getcwd(), encryption_key)
        if self.py_inst_archive.pyc:
            decompile_entry_points(self.py_inst_archive.pyc)

    def __pyinstxtractor_extract(self):
        if self.py_inst_archive.getCArchiveInfo():
            self.py_inst_archive.parseTOC()
            self.py_inst_archive.extractFiles()
            printInfo(f'Finished extracting {self.file_path}. . .')

    def unpack(self, filename):
        self.__pyinstxtractor_extract()
        self.__decrypt()
        printSucc(f'Successfully unpacked {filename}')


class Py2Exe(BinaryHandler):
    def magic_recogniser(self):
        self.open_executable()
        is_py2exe = False
        script_resource = None
        self.pe_file = pefile.PE(self.file_path)

        if hasattr(self.pe_file, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                if str(entry.name) == str("PYTHONSCRIPT"):
                    script_resource = entry.directory.entries[0].directory.entries[0]
                    break

        if script_resource != None:
            rva = script_resource.data.struct.OffsetToData
            size = script_resource.data.struct.Size
            dump = self.pe_file.get_data(rva, size)
            current = struct.calcsize(b'iiii')
            metadata = struct.unpack(b'iiii', dump[:current])
            if hex(metadata[0]) == "0x78563412":
                is_py2exe = True

        self.close()
        return is_py2exe

    def pyver(self):
        if hasattr(self.pe_file, 'DIRECTORY_ENTRY_RESOURCE'):
            for entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries:
                if ('PYTHON' and '.DLL') in str(entry.name):
                    ver = str(entry.name).strip("PYTHON").strip(".DLL")
                    printInfo(f'Compiled with Python {ver}')
                    ver = int(ver)
        if not isinstance(ver, int):
            ver = sys.version_info.major + sys.version_info.minor
        return ver

    def unpack(self, filename):
        try:
            unpy2exe(filename, self.extraction_dir)
        except Exception as e:
            # python 2 and 3 marshal data differently and has different implementation and unfortunately unpy2exe depends on marshal.
            printErr('Failed to unpack. Most likely due to version incompability (exe created using python 2)')
            printErrStack(e)


def main(file_path: str):
    BinaryHandler.check(file_path)  # check for invalid input

    output = os.path.basename(file_path)
    if os.path.exists(os.path.join(os.getcwd(), output)) and not os.path.isdir(os.path.join(os.getcwd(), output)):
        printErr(f'{output} is in the current directory. Please move it to somewhere else so PyExtractor can properly analyze it.')
        Logging.log_close()

    # construct the classes
    Config()
    analyse = Analyse(file_path)
    pyinstaller = PyInstaller(file_path, output)
    py2exe = Py2Exe(file_path, output)

    # check if it's pyinstaller or py2exe which PyExtractor can unpack
    if pyinstaller.magic_recogniser():
        printInfo(f'{output} was compiled with pyinstaller')
        pyinstaller.unpack(file_path)
        analyse.start()

    elif py2exe.magic_recogniser():
        printInfo(f'{output} was compiled with py2exe')
        py2exe.unpack(file_path)
        analyse.start()
    else:
        printWarn('Unrecognizable packer, proceeding with normal checking. . .')
        analyse.start(folder=False)

    pyinstaller.close()
    py2exe.close()
    Logging.log_close()


if __name__ == "__main__":
    if not sys.version_info[:2] >= (3, 8):
        printErr('''Your current python version ({}.{}.{}), is not supported. 
            Please run "{}" in python 3.8+'''.format(
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
            os.path.basename(__file__)
        ))
        sys.exit(-1)

    def handler(signal, frame):
        Logging.log_close(exit_code='Goodbye!')

    signal(SIGINT, handler)
    print(banner())
    _file = input('Drag/Type your executable here: ').strip('"').strip("'")
    main(_file)
