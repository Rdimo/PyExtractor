import os
import abc
import pefile
from time import sleep
from utilities import printErrStack, printInfo, printWarn, printErr, Logging


class BinaryHandler(object):
    """
    base handler for binaries and folders:

        - open_executable()
        - close()

    Raises a FileNotFoundError when given file is not found:

    >>> Traceback (most recent call last):
      ...
    FileNotFoundError: cant find <file> on your device

    """
    __metaclass__ = abc.ABCMeta

    def __init__(self, path, output_dir):
        self.file_path = path

        self.extraction_dir = output_dir
        if not os.path.exists(self.extraction_dir):
            os.makedirs(self.extraction_dir, exist_ok=True)

    def open_executable(self):
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError

            self.fPtr = open(self.file_path, 'rb')
            self.fileSize = os.stat(self.file_path).st_size

        except FileNotFoundError:
            printErr(f"Can't find {self.file_path} on your device")
            Logging.log_close()

        except Exception:
            printWarn(f'Having Trouble opening {self.file_path}')
            sleep(1)
            printInfo('Proceeding with normal checking. . .')

    def close(self):
        try:
            self.fPtr.close()
        except Exception:
            pass

    @staticmethod
    def check(_file):
        printInfo(f'Processing {_file}')
        if not os.path.exists(_file):
            printErr(f'can\'t find "{_file}" on your device')
            Logging.log_close()

        if not os.path.isfile(_file):
            printErr(f'"{_file}" needs to be a file!')
            Logging.log_close()

        if not _file.endswith('.exe'):
            printErr(f'"{_file}" needs to be an executable!')
            Logging.log_close()

        try:
            pe_file = pefile.PE(_file)
            if not (pe_file.is_dll() or pe_file.is_exe()):
                printErr(f'"{_file}" is not an executable!')
                Logging.log_close()
        except Exception as e:
            printErr(f'Error occured while validating {_file}')
            printErrStack(e)
            Logging.log_close()
