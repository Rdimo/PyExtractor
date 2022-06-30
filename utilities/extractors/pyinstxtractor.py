# https://github.com/extremecoders-re/pyinstxtractor
import os
import sys
import zlib
import struct
import marshal
from uuid import uuid4 as uniquename
from importlib.util import MAGIC_NUMBER as pyc_magic
from utilities import printInfo, printWarn, printErr


class CTOCEntry:
    def __init__(self, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive():
    PYINST20_COOKIE_SIZE = 24           # Pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64      # Pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic

    def __init__(self, path):
        self.filePath = path
        self.pyc = []

    def open(self):
        try:
            self.fPtr = open(self.filePath, 'rb')
            self.fileSize = os.stat(self.filePath).st_size
        except:
            printErr(f'Failed to open {self.filePath}')
            return False
        return True

    def checkFile(self):
        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            printErr('File is too small or truncated')
            return False

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self.fPtr.seek(startPos, os.SEEK_SET)
            data = self.fPtr.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            return False

        self.fPtr.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self.fPtr.read(64):
            self.pyinstVer = 21     # pyinstaller 2.1+
        else:
            self.pyinstVer = 20     # pyinstaller 2.0

        return True

    def getCArchiveInfo(self):
        try:
            if self.pyinstVer == 20:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver) = \
                    struct.unpack('!8siiii', self.fPtr.read(
                        self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self.fPtr.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, self.pyver, pylibname) = \
                    struct.unpack('!8siiii64s', self.fPtr.read(
                        self.PYINST21_COOKIE_SIZE))

        except:
            return False

        printInfo(f'Compiled with Python {self.pyver}')

        tailBytes = self.fileSize - self.cookiePos - \
            (self.PYINST20_COOKIE_SIZE if self.pyinstVer ==
             20 else self.PYINST21_COOKIE_SIZE)

        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        printInfo(f'Package bytes length: {lengthofPackage}')
        return True

    def parseTOC(self):
        self.fPtr.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        while parsedLen < self.tableOfContentsSize:
            (entrySize, ) = struct.unpack('!i', self.fPtr.read(4))
            nameLen = struct.calcsize('!iiiiBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
                struct.unpack(
                '!iiiBc{0}s'.format(entrySize - nameLen),
                self.fPtr.read(entrySize - 4))

            name = name.decode('utf-8').rstrip('\0')
            if len(name) == 0:
                name = str(uniquename())
                printWarn(f'unamed file found. applying random name {name}')

            self.tocList.append(
                CTOCEntry(
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name
                ))

            parsedLen += entrySize
        printInfo(f'{len(self.tocList)} files found in CArchive')

    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace(
            '/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        # Check if path exists, create if not
        if nmDir != '' and not os.path.exists(nmDir):
            os.makedirs(nmDir)
        try:
            with open(nm, 'wb') as f:
                f.write(data)
        except PermissionError as e:
            printWarn(e)

    def extractFiles(self):
        printInfo(f'Extracting {self.filePath}. . .')
        base = os.path.basename(self.filePath)
        extractionDir = os.path.join(os.getcwd(), base, 'Extracted')

        if not os.path.exists(extractionDir):
            os.makedirs(extractionDir)
        os.chdir(extractionDir)

        for entry in self.tocList:
            basePath = os.path.dirname(entry.name)
            absPath = os.path.abspath(entry.name + '.pyc')
            if basePath != '':
                if not os.path.exists(basePath):
                    os.makedirs(basePath)
            if "_pytransform" in entry.name.lower():
                printWarn(f'Pyarmor detected: {entry.name}')
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                data = zlib.decompress(data)
                assert len(data) == entry.uncmprsdDataSize

            if entry.typeCmprsData == b's':
                self.pyc.append(absPath)
                self._writePyc(entry.name + '.pyc', data)

            elif entry.typeCmprsData.lower() == b'm':
                self._writeRawData(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData.lower() == b'z':
                    self._extractPyz(entry.name)

    def _writePyc(self, filename, data):
        try:
            with open(filename, 'wb') as pycFile:
                pycFile.write(pyc_magic)

                if self.pyver >= 37:
                    pycFile.write(b'\0' * 4)
                    pycFile.write(b'\0' * 8)

                else:
                    pycFile.write(b'\0' * 4)
                    if self.pyver >= 33:
                        pycFile.write(b'\0' * 4)

                pycFile.write(data)
        except PermissionError:
            printErr(f'Access Denied {filename}')

    def _extractPyz(self, name):
        dirName = name + '_extracted'
        if not os.path.exists(dirName):
            os.makedirs(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0'
            pycHeader = f.read(4)

            if pyc_magic != pycHeader:
                printWarn(
                    f'script was ran using python {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]} while executable was built with python {self.pyver}')
                printWarn(
                    f'Run this script in Python {self.pyver} to prevent possible extraction errors during unmarshalling')

            (tocPosition, ) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                printWarn(
                    f'Failed to unmarshal {name}. Extracting remaining files. . .')
                return
            printInfo(f'Found {len(self.pyc)} possible entry points')
            printInfo(f'Found {len(toc)} files in PYZ archive')

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode('utf-8')
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace(
                    '..', '__').replace('.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except PermissionError:
                    printErr(f'Access Denied {fileName}')
                except Exception:
                    # printWarn(
                    # f'Failed to decompress {fileName} most likely encrypted. Extracting as is.')
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)
