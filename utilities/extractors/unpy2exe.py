# originally from https://github.com/matiasb/unpy2exe/blob/master/unpy2exe.py
# may have some errors with later versions

import os
import six
import struct
import pefile
import ntpath
import marshal
from shutil import move, Error
from utilities import printInfo
import utilities.modules.pyc_decompile as umpd

IGNORE = [
    # added by py2exe
    '<bootstra.pyc',
    '<install zipextimport.pyc',
    '<boot hac.pyc',
    'boot_common.pyc',
]


def get_current_magic():
    from importlib.util import MAGIC_NUMBER
    return MAGIC_NUMBER


def _get_scripts_resource(pe):
    res = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name and entry.name.string == b"PYTHONSCRIPT":
            res = entry.directory.entries[0].directory.entries[0]
            break
    return res


def _resource_dump(pe, res):
    rva = res.data.struct.OffsetToData
    size = res.data.struct.Size

    dump = pe.get_data(rva, size)
    return dump


def _get_co_from_dump(data):
    current = struct.calcsize(b'iiii')
    meta = struct.unpack(b'iiii', data[:current])
    printInfo(f'Package bytes length: {meta[3]}')
    arcname = ''
    while six.indexbytes(data, current) != 0:
        arcname += chr(six.indexbytes(data, current))
        current += 1
    if arcname:
        printInfo(f"Archive name: {arcname}")
    code_bytes = data[current + 1:]
    code_objects = marshal.loads(code_bytes)
    return code_objects


def extract_code_objects(pe):
    printInfo('Extracting binary. . .')
    script_res = _get_scripts_resource(pe)
    dump = _resource_dump(pe, script_res)
    return _get_co_from_dump(dump)


def _generate_pyc_header(IO):
    magic = get_current_magic()
    IO.write(magic + b'\0' * (16 - len(magic)))


def dump_to_pyc(co, output_dir):
    pyc_basename = ntpath.basename(co.co_filename)
    pyc_name = pyc_basename[:-3] + '.pyc'

    if pyc_name not in IGNORE:
        printInfo(f'pyc file found! - {pyc_name}')
        marshaled_code = marshal.dumps(co)
        destination = os.path.join(output_dir, pyc_name)

        try:
            with open(destination, 'wb') as pyc:
                _generate_pyc_header(pyc)
                pyc.write(marshaled_code)
        except OSError:
            pass

        src = os.path.join(output_dir, 'Source_code')
        extracted = os.path.join(output_dir, 'Extracted')
        if not ntpath.exists(src):
            os.makedirs(src)
        if not ntpath.exists(extracted):
            os.makedirs(extracted)

        umpd.decompile_pyc(destination, src + os.sep + pyc_name[:-3] + 'py', log=True)
        try:
            move(destination, extracted)
        except Error:
            os.remove(destination)


def unpy2exe(filename, output_dir='.'):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    pe = pefile.PE(filename)

    code_objects = extract_code_objects(pe)
    for co in code_objects:
        dump_to_pyc(co, output_dir)
