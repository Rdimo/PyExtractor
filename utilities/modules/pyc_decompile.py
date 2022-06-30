import subprocess
from utilities import printSucc
from os import PathLike, getcwd, makedirs, pardir, path, sep, walk


def decompile_entry_points(entry_points):
    for pyc in entry_points:
        out_dir = path.abspath(path.join(path.abspath(path.join(pyc, pardir)), pardir)) + sep + 'Source_Code'
        if not path.exists(out_dir):
            makedirs(out_dir)
        decompile_pyc(pyc, out_dir + sep + path.basename(pyc)[:-4] + '.py', log=True, _path=path.join(pardir, pardir))


def decompile_pyc(pyc_file: PathLike or str, output: PathLike or str, log=False, _path=getcwd()):
    process = subprocess.Popen(f"{_path}/utilities/bin/pycdc.exe {pyc_file}", stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    decompiled = process.communicate()[0].decode()

    with open(file=f"{output}", mode="wt", errors="replace", newline='') as f:
        f.write(decompiled)
    if log:
        printSucc(f'Decompiled {path.basename(pyc_file)} --> {path.basename(output)}')


def get_pyc_files(pyc_directory, extension=".pyc") -> list:
    pyc_list = []
    for _, __, files in walk(pyc_directory):
        for _file in files:
            if _file.endswith(extension):
                pyc_list.append(_file)
    return pyc_list
