import sys
import time
from .colors import colors
from typing import NoReturn
from typing_extensions import Literal, TypeAlias

logFile = 'logs.log'
_file = open(logFile, 'a')


class Logging:
    @classmethod
    def stamp(cls, stmp):
        from utilities import Config
        return f'{f"{time.ctime()} ::" if Config.get_setting("time_stamp_logging") else ""} [{stmp}]'

    @classmethod
    def type_check(cls, _type: TypeAlias = Literal["success", "info", "normal", "warn", "error", "error_stack"]):
        if _type == "success":
            return cls.stamp('#')
        elif _type == "info":
            return cls.stamp('*')
        elif _type == "warn":
            return cls.stamp('!')
        elif _type == "error":
            return cls.stamp('x')
        elif _type == "error_stack":
            return cls.stamp('X')
        elif _type == "normal":
            return cls.stamp('')
        else:
            return cls.stamp('*')

    @staticmethod
    def file_log(text, stamp, newLine=True):
        _file.write(str(stamp))
        _file.write(str(text))
        if newLine:
            _file.write('\n')

    @staticmethod
    def log_close(exit_code=1) -> NoReturn:
        _file.write('Finished'.center(60, "-"))
        _file.write('\n' * 2)
        _file.close()
        sys.exit(exit_code)


def logger(_type: TypeAlias = Literal["success", "info", "normal", "warn", "error", "error_stack"]):
    def decorator(func):
        def wrapper(*args, **kwargs):
            func(*args, **kwargs)
            Logging.file_log(*args, Logging.type_check(_type))
        return wrapper
    return decorator


def bracket(_type, col):
    return '{}[{}{}{}]{}'.format(colors.black, col, _type, colors.black, colors.white)


@logger(_type="success")
def printSucc(msg):
    print("{} {}".format(bracket(_type='+', col=colors.green), msg))


@logger(_type="info")
def printInfo(msg):
    print("{} {}".format(bracket(_type='*', col=colors.cyan), msg))


@logger(_type="normal")
def printNormal(msg):
    print("{}".format(msg))


@logger(_type="warn")
def printWarn(msg):
    print("{} {}".format(bracket(_type='!', col=colors.yellow), msg))


@logger(_type="error")
def printErr(msg):
    print("{} {}".format(bracket(_type='x', col=colors.red), msg))


@logger(_type="error_stack")
def printErrStack(msg):
    from utilities import Config
    if Config.get_setting('error_stack_logs'):
        print("{}".format(bracket(_type='X', col=colors.red)))
        err = str(msg).splitlines()
        for i, v in enumerate(err):
            val = v.strip(' ')
            if val:
                print(":   {}".format(val))
        print("{}".format(bracket(_type='X', col=colors.red)))
