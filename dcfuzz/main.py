import os
import sys
import logging
import pathlib
import subprocess
import threading
import time
import signal
import atexit
import datetime

import math
import random
import traceback

from pathlib import Path
from typing import Dict, List, Optional


from . import cli
from . import config as Config
from . import fuzzer_driver # , sync, fuzzing
from .common import nested_dict

# set log file

logger = logging.getLogger('DCFuzz.main')
logging.basicConfig(level=logging.INFO, filename='logDCFuzz.log',filemode='w', format='%(filename)s-%(funcName)-10s-%(message)s')
#logging.basicConfig(level=logging.INFO, filename='logDCFuzz.log',filemode='w', format='%(asctime)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')

LOG = nested_dict()

# Global variable
START_TIME: float = 0.0
config: Dict = Config.CONFIG
OUTPUT: Path
INPUT: Optional[Path]

TIMEOUT: int
PREP_TIME: int
FOCUS_TIME: int
START_TIME:float = 0.0

SLEEP_GRANULARITY: int = 60

FUZZERS: List[str]= []
TARGET: str
CPU_ASSIGN: Dict[str, float] = {}
CGROUP_ROOT = ''

ARGS: cli.ArgsParser

def terminate_dcfuzz():
    global DCFUZZ_PID
    logger.critical('terminate dcfuzz because of error')
    cleanup(1)

def check_fuzzer_ready_one(fuzzer):
    global ARGS, FUZZERS, TARGET, OUTPUT
    # NOTE: fuzzer driver will create a ready file when launcing
    ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
    if not os.path.exists(ready_path):
        return False
    return True


def gen_fuzzer_driver_args(fuzzer: str,
                           jobs=1,
                           input_dir=None,
                           ) -> dict:
    global ARGS, CGROUP_ROOT

    fuzzer_config = config['fuzzer'][fuzzer]
    target_config = config['target'][TARGET]

    seed = None
    if input_dir:
        seed = input_dir
    else:
        seed = target_config['seed']
    group = target_config['group']
    target_args = target_config['args'].get(fuzzer, target_config['args']['default'])

    logging.info(f'main 200- target_args : {target_args}')

    root_dir = os.path.realpath(ARGS.output)
    output = os.path.join(root_dir, TARGET, fuzzer)
    #cgroup_path = os.path.join(CGROUP_ROOT, fuzzer)
    kw = {
        'fuzzer': fuzzer,
        'seed': seed,
        'output': output,
        'group': group,
        'program': TARGET,
        'argument': target_args,
        'thread': jobs
        #'cgroup_path': cgroup_path
    }
    return kw

def start(fuzzer: str, output_dir, timeout, input_dir=None):
    global FUZZERS,ARGS

    logger.info(f'main 100 - start function {fuzzer} ')

    fuzzer_config = config['fuzzer'][fuzzer]
    create_output_dir = fuzzer_config.get('create_output_dir',True)
    if create_output_dir:
        host_output_dir = f'{output_dir}/{ARGS.target}/{fuzzer}'
        logger.info(f'main 101 - create_output_dir : {create_output_dir}  host_output_dir : {host_output_dir}')
        os.makedirs(host_output_dir, exist_ok=True)
    else:
        host_output_dir = f'{output_dir}/{ARGS.target}'
        if os.path.exists(f'{output_dir}/{ARGS.target}/{fuzzer}'):
            logger.error(f'Please remove {output_dir}/{ARGS.target}/{fuzzer}')
            terminate_rcfuzz()
        os.makedirs(host_output_dir, exist_ok=True)

        logger.info(f'main 101_2 - create_output_dir : {create_output_dir}  host_output_dir : {host_output_dir}')
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)

    kw['command'] = 'start'

    logger.info(f'main 102 - start func kw : {kw}')

    fuzzer_driver.main(**kw)

def pause(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to pause fuzzer
    '''
    logger.info(f'main 103 - pause function {fuzzer}')

    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)

    kw['command'] = 'pause'

    logger.info(f'main 104 - pause func kw : {kw}')

    fuzzer_driver.main(**kw)

# def update_fuzzer_log(fuzzers):
#     global LOG

#     logger.info(f'main 301 - update fuzzer')

#     new_log_entry = maybe_get_fuzzer_info(fuzzers)
#     if not new_log_entry: return
#     new_log_entry = compress_fuzzer_info(fuzzers, new_log_entry)
    
#     new_log_entry['timestamp'] = time.time()
#     # NOTE: don't copy twice
#     append_log('log', new_log_entry, do_copy=False)


# def thread_update_fuzzer_log(fuzzers):
#     logger.info(f'main 300 - thread update fuzzer')
#     update_time = min(60, PREP_TIME, SYNC_TIME, FOCUS_TIME)
#     while not is_end():
#         update_fuzzer_log(fuzzers)
#         time.sleep(update_time)

# # crash mode and empty_seed 는 필요 없음.
# # distance 구하는 이미지가 필요함.

# def maybe_get_fuzzer_info(fuzzers) -> Optional[Coverage]:

#     logger.info(f'main 400 - maybe get fuzzer info')

#     logger.debug('get_fuzzer_info called')

#     new_fuzzer_info = nested_dict()

#     for fuzzer in fuzzers:
#         result = coverage.thread_run_fuzzer(TARGET,
#                                             fuzzer,
#                                             FUZZERS,
#                                             OUTPUT,
#                                             ARGS.timeout,
#                                             '10s')
#         if result is None:
#             logger.debug(f'get_fuzzer_info: {fuzzer}\'s cov is None')
#             return None
#         cov = result['coverage']
#         unique_bugs = result['unique_bugs']
#         bitmap = result['bitmap']
#         new_fuzzer_info['coverage'][fuzzer] = cov
#         new_fuzzer_info['unique_bugs'][fuzzer] = unique_bugs
#         new_fuzzer_info['bitmap'][fuzzer] = bitmap
#         line_coverage = cov['line_coverage']
#         line = cov['line']
#         logger.debug(
#             f'{fuzzer} has line_coverge {line_coverage} line {line}, bugs {unique_bugs}'
#         )

#     global_result = coverage.thread_run_global(TARGET,
#                                                FUZZERS,
#                                                OUTPUT,
#                                                ARGS.timeout,
#                                                '10s',
#                                                empty_seed=ARGS.empty_seed,
#                                                crash_mode=ARGS.crash_mode)
#     if global_result is None: return None
#     cov = global_result['coverage']
#     unique_bugs = global_result['unique_bugs']
#     bitmap = global_result['bitmap']
#     new_fuzzer_info['global_coverage'] = cov
#     new_fuzzer_info['global_unique_bugs'] = unique_bugs
#     new_fuzzer_info['global_bitmap'] = bitmap
#     logger.debug(f'global has line_coverge {cov["line"]}, bugs {unique_bugs}')

#     return new_fuzzer_info


def cleanup(exit_code=0):
    global ARGS
    logger.info('main 666 - cleanup')
    LOG['end_time'] = time.time()
    #write_log()
    #for fuzzer in FUZZERS:
    #    stop(fuzzer)
    #if exit_code == 0 and ARGS.tar:
    #    save_tar()
    os._exit(exit_code)


def cleanup_exception(etype, value, tb):
    #traceback.print_exception(etype, value, tb)
    cleanup(1)


def write_log():
    global LOG, RUNNING
    if not RUNNING:
        logger.info('main 901 - Not RUNNING, No log')
        return
    if OUTPUT and LOG_FILE_NAME:
        with open(f'{OUTPUT}/{LOG_FILE_NAME}', 'w') as f:
            f.write(json.dumps(LOG, default=json_dumper))
    else:
        assert False, 'update_log error'


def init():
    global START_TIME, LOG
    signal.signal(signal.SIGTERM, lambda x, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, frame: sys.exit(0))
    atexit.register(cleanup)
    sys.excepthook = cleanup_exception
    health_check_path = os.path.realpath(os.path.join(ARGS.output, 'health'))
    pathlib.Path(health_check_path).touch(mode=0o666, exist_ok=True)
    LOG['log'] = []
    LOG['round'] = []
    logger.info(f'main 004.5 - init end')

# we create init_cgroup



def main():
    global ARGS, TARGET, FUZZERS, OUTPUT, INPUT
    global TIMEOUT, PREP_TIME, FOCUS_TIME, START_TIME
    global CPU_ASSIGN


    ARGS = cli.ArgsParser().parse_args()

    logger.info(f'main 001 - ARG(user set option) : {ARGS}\n')

    # option parsing
    TARGET = ARGS.target
    FUZZERS = ARGS.fuzzer
    OUTPUT = ARGS.output.resolve()
    TIMEOUT = ARGS.timeout
    PREP_TIME = ARGS.prep
    FOCUS_TIME = ARGS.focus

    if ARGS.input:
        INPUT = ARGS.input.resolve()
    else:
        INPUT = None

    logger.info(f'main 002 - check ARG : target : {TARGET}, fuzzer : {FUZZERS}, output : {OUTPUT}, timeout : {TIMEOUT}, prep_time : {PREP_TIME}, focus_time :{FOCUS_TIME}')

    # create output directory
    try:
        os.makedirs(OUTPUT, exist_ok=False)
    except FileExistsError:
        logger.error(f'remove {OUTPUT}')
        exit(1)
    
    current_time = time.time()
    init()
    LOG['dcfuzz_args'] = ARGS.as_dict()  # remove Namespace
    LOG['dcfuzz_config'] = config
    LOG['start_time'] = current_time
    LOG['algorithm'] = None

    # setup each fuzzer
    for fuzzer in FUZZERS:
        logger.info(f'main 003 - warm up {fuzzer}')
        CPU_ASSIGN[fuzzer] = 0

        # start each fuzzer in process
        logger.info(f'main 004 - start before')
        start(fuzzer=fuzzer, output_dir = OUTPUT, timeout=TIMEOUT, input_dir=INPUT)
        logger.info(f'main 004.5 - start after')  

        time.sleep(2)
        start_time = time.time()
        while not check_fuzzer_ready_one(fuzzer):
            current_time = time.time()
            elasp = current_time - start_time
            if elasp > 180:
                logger.critical('fuzzers start up error')
                terminate_dcfuzz()
            logger.info(f'main 666_2 - fuzzer not {fuzzer} ready, sleep 10 seconds to warm up')

        logger.info(f'main 005 - pause before')
        try:
            pause(fuzzer=fuzzer, jobs=1, input_dir=INPUT)
            logger.info(f'main 005.5 - pause after')
        except Exception as e:
            logger.exception(f'main 005.5 - pause error : %r',e)
        

    logger.info(f'main 999 - end program')


        

    # LOG_DATETIME = f'{datetime.datetime.now():%Y-%m-%d-%H-%M-%S}'
    # LOG_FILE_NAME = f'{TARGET}_{LOG_DATETIME}.json'

    #thread_fuzzer_log = threading.Thread(target=thread_update_fuzzer_log, kwargs={'fuzzers': FUZZERS}, daemon=True)
        
    # thread_fuzzer_log.start()
        
    # thread_health = threading.Thread(target=thread_health_check, daemon=True)
    # thread_health.start()

    # scheduler = None
    # algorithm = None

    # if ARGS.focus_one:
    #     scheduler = Schedule_Focus(fuzzers=FUZZERS, focus=ARGS.focus_one)
    #     algorithm = ARGS.focus_one

    # else:
    #     scheduler = Schedule_DCFuzz(fuzzers=FUZZERS, dcFuzzers=dcFuzzers,
    #                                   prep_time=PREP_TIME,
    #                                   focus_time=FOCUS_TIME,
    #                                   diff_threshold=1)
    #     algorithm = 'dcfuzz'
    
    # LOG['algorithm'] = algorithm

    # RUNNING = True

    # thread_log = threading.Thread(target=thread_write_log, daemon=True)
    # thread_log.start()
    
    

    # # Timer to stop all fuzzers
    # logger.info(f'main 038 - algorithm : {algorithm}, scheduler: {scheduler}')

    # scheduler.run()

    # finish_path = os.path.join(OUTPUT, 'finish')
    # pathlib.Path(finish_path).touch(mode=0o666, exist_ok=True)
    # while not is_end_global():
    #     logger.info('main 039 - sleep to wait final coverage')
    #     time.sleep(300)

    # LOG['end_time'] = time.time()

    # write_log()
    # logger.info(f'main 999 - end program')
    # cleanup(0)


if __name__ == '__main__':
    main()
