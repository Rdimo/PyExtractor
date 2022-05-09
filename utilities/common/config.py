import json
import ntpath
from os import getcwd, sep, stat
from utilities import printWarn
from dataclasses import dataclass


@dataclass
class Config(object):
    config_dir = getcwd() + sep + 'config.json'
    defaults = {
        "detailed_logs": False,
        "error_stack_logs": True,
        "time_stamp_logging": True,

        "analyse_file": True,
        "malware_recognize": True
    }

    def __init__(self):
        self.config_dir = self.__class__.config_dir
        self.defaults = self.__class__.defaults

        if not ntpath.exists(self.config_dir):
            printWarn(
                f'config.json not found! Creating one --> {self.config_dir}')
            self.create_config()

        if stat(self.config_dir).st_size == 0:
            printWarn(
                f'config.json is empty! Applying defaults --> {self.config_dir}')
            self.create_config()

    def create_config(self):
        with open(self.config_dir, 'w') as f:
            json.dump(
                self.defaults, f,
                ensure_ascii=False,
                indent=4,
                sort_keys=True
            )

    @classmethod
    def get_setting(cls, setting):
        with open(cls.config_dir) as json_:
            data = json.load(json_)
        # if the config has empty dict in it
        if not bool(data):
            printWarn(
                f'config.json is empty! Applying defaults --> {cls.config_dir}')
            cls.create_config()
        return data[setting]
