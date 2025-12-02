import glob
import hashlib
import logging
import os
import pathlib
import time
from pathlib import Path
from typing import Dict, List

from . import config as Config
from . import utils, watcher
from .common import nested_dict
from .mytype import Fuzzer, Fuzzers, FuzzerType

config = Config.CONFIG

logger = logging.getLogger('dcfuzz.sync')

hashmap: Dict[str, str] = dict()
time_for_hash: float = 0




