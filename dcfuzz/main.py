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
import json

import math
import random
import traceback

from abc import abstractmethod
from pathlib import Path
from typing import Dict, List, Optional
from cgroupspy import trees


from . import cgroup_utils, cli
from . import config as Config
from . import fuzzer_driver, sync #, fuzzing
from .common import nested_dict, IS_PROFILE, IS_DEBUG
from .singleton import SingletonABCMeta

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
LOG_DATETIME: str
LOG_FILE_NAME: str

TIMEOUT: int
PREP_TIME: int
FOCUS_TIME: int
START_TIME:float = 0.0

SLEEP_GRANULARITY: int = 60

RUNNING: bool = False

FUZZERS: List[str]= []
TARGET: str
CPU_ASSIGN: Dict[str, float] = {}
CGROUP_ROOT = ''

ARGS: cli.ArgsParser

def terminate_dcfuzz():
    global DCFUZZ_PID
    logger.critical('terminate dcfuzz because of error')
    cleanup(1)

def is_end():
    logger.info('main 900 - check end time')
    global START_TIME
    diff = 60
    current_time = time.time()
    elasp = current_time - START_TIME
    timeout_seconds = TIMEOUT
    # logger.info(f'main 900 - elasp : {elasp}, timeout_seconds :{timeout_seconds}, current_time : {current_time}, START_TIME : {START_TIME} ')
    return elasp >= timeout_seconds + diff



def check_fuzzer_ready_one(fuzzer):
    global ARGS, FUZZERS, TARGET, OUTPUT
    # NOTE: fuzzer driver will create a ready file when launcing
    ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
    if not os.path.exists(ready_path):
        return False
    return True

def sleep(seconds: int, log=False):
    logger.info(f'main 901 -  sleep time: {seconds}, log: {log}')
    '''
    hack to early return
    '''
    global SLEEP_GRANULARITY
    if log:
        logger.info(f'main 902 - sleep {seconds} seconds')
    else:
        logger.debug(f' sleep {seconds} seconds')
    remain = seconds
    while remain and not is_end():
        t = min(remain, SLEEP_GRANULARITY)
        logger.info(f'main 903 - remain: {remain}, SLEEP_GRAUNLARITY: {SLEEP_GRANULARITY}, t : {t}')
        time.sleep(t)
        remain -= t

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
    cgroup_path = os.path.join(CGROUP_ROOT, fuzzer)
    kw = {
        'fuzzer': fuzzer,
        'seed': seed,
        'output': output,
        'group': group,
        'program': TARGET,
        'argument': target_args,
        'thread': jobs,
        'cgroup_path': cgroup_path
    }
    return kw

def start(fuzzer: str, output_dir, timeout, input_dir=None):
    global FUZZERS,ARGS

    # logger.info(f'main 100 - start function {fuzzer} ')

    fuzzer_config = config['fuzzer'][fuzzer]
    create_output_dir = fuzzer_config.get('create_output_dir',True)
    if create_output_dir:
        host_output_dir = f'{output_dir}/{ARGS.target}/{fuzzer}'
        # logger.info(f'main 101 - create_output_dir : {create_output_dir}  host_output_dir : {host_output_dir}')
        os.makedirs(host_output_dir, exist_ok=True)
    else:
        host_output_dir = f'{output_dir}/{ARGS.target}'
        if os.path.exists(f'{output_dir}/{ARGS.target}/{fuzzer}'):
            logger.error(f'Please remove {output_dir}/{ARGS.target}/{fuzzer}')
            terminate_dcfuzz()
        os.makedirs(host_output_dir, exist_ok=True)

        # logger.info(f'main 101_2 - create_output_dir : {create_output_dir}  host_output_dir : {host_output_dir}')
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)

    kw['command'] = 'start'

    # logger.info(f'main 102 - start func kw : {kw}')

    fuzzer_driver.main(**kw)

def pause(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to pause fuzzer
    '''
    # logger.info(f'main 103 - pause function {fuzzer}')

    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, input_dir=input_dir)

    kw['command'] = 'pause'

    # logger.info(f'main 104 - pause func kw : {kw}')

    fuzzer_driver.main(**kw)

def resume(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to resume fuzzer
    '''
    # logger.info(f'main 105 - resume function {fuzzer}')
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer, jobs=1, input_dir=input_dir)

    kw['command'] = 'resume'

    # logger.info(f'main 106 - resume func kw : {kw}')

    fuzzer_driver.main(**kw)

def stop(fuzzer, jobs=1, input_dir=None):
    '''
    call Fuzzer API to stop fuzzer
    '''
    # logger.info(f'main 107 - stop function {fuzzer}')
    
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,jobs=1, input_dir=input_dir)

    kw['command'] = 'stop'

    # logger.info(f'main 108 - stop func kw : {kw}')

    fuzzer_driver.main(**kw)


# sync the seed and remove depulicated seed 
def do_sync(fuzzers: List[str], host_root_dir: Path) -> bool:
    logger.info('main 109 - start seed sync')
    #fuzzer_info = maybe_get_fuzzer_info(fuzzers)
    #if not fuzzer_info:
    #    return False
    start_time = time.time()
    logger.info(f'main 110 - TARGET : {TARGET}, fuzzers : {fuzzers}, host_root_dir : {host_root_dir}')
    sync.sync2(TARGET, fuzzers, host_root_dir)
    end_time = time.time()
    diff = end_time - start_time
    if IS_PROFILE: logger.info(f'main 110 - sync take {diff} seconds')
    #coverage.sync()
    return True

def set_fuzzer_cgroup(fuzzer, new_cpu):
    global CGROUPR_ROOT
    p = os.path.join('/cpu', CGROUP_ROOT[1:], fuzzer)
    t = trees.Tree()
    fuzzer_cpu_node = t.get_node_by_path(p)
    cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us
    quota = int(cfs_period_us * new_cpu)
    # NOTE: minimal possible number for cgroup
    if quota < 1000:
        quota = 1000
    logger.debug(f'set fuzzer cgroup {fuzzer} {new_cpu} {quota}')
    fuzzer_cpu_node.controller.cfs_quota_us = quota


def update_fuzzer_limit(fuzzer, new_cpu):
    logger.info('main 400 - update fuzzer limit start')
    global ARGS, CPU_ASSIGN, INPUT
    if fuzzer not in CPU_ASSIGN: return
    if math.isclose(CPU_ASSIGN[fuzzer], new_cpu):
        return
    is_pause = math.isclose(0, new_cpu)
    # logger.info(f'main 401 - is_pause : {is_pause}')

    if is_pause:        
        # print('update pause')
        pause(fuzzer=fuzzer, jobs=1, input_dir=INPUT)

    # previous 0
    if math.isclose(CPU_ASSIGN[fuzzer], 0) and new_cpu != 0:
        # logger.info(f'main 401.5 - resume start')
        resume(fuzzer=fuzzer, jobs=1, input_dir=ARGS.input)  

    CPU_ASSIGN[fuzzer] = new_cpu

    # setup cgroup
    if not is_pause:
        set_fuzzer_cgroup(fuzzer, new_cpu)
    else:
        # give 1%
        set_fuzzer_cgroup(fuzzer, 0.01)
    # logger.info('main 402 - update fuzzer limit end')

# # crash mode and empty_seed 는 필요 없음.
# # distance 구하는 이미지가 필요함.

def cleanup(exit_code=0):
    global ARGS
    logger.info('main 666 - cleanup')
    LOG['end_time'] = time.time()
    write_log()
    for fuzzer in FUZZERS:
       stop(fuzzer)
    #if exit_code == 0 and ARGS.tar:
    #    save_tar()
    os._exit(exit_code)


def cleanup_exception(etype, value, tb):
    #traceback.print_exception(etype, value, tb)
    cleanup(1)


def write_log():
    global LOG, RUNNING
    if not RUNNING:
        logger.info('main 666 - Not RUNNING, No log')
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
    logger.info(f'main 002.5- init end')

def init_cgroup():
    logger.info(f'main 200 - cgroup init start')

    '''
    cgroup /dcfuzz is created by /init.sh, the command is the following:
    cgcreate -t yufu -a yufu -g cpu:/dcfuzz
    '''

    global FUZZERS, CGROUP_ROOT
    # start with /
    cgroup_path = cgroup_utils.get_cgroup_path()
    container_id = os.path.basename(cgroup_path)
    cgroup_path_fs = os.path.join('/sys/fs/cgroup/cpu', cgroup_path[1:])
    dcfuzz_cgroup_path_fs = os.path.join(cgroup_path_fs, 'dcfuzz')

    if not os.path.exists(dcfuzz_cgroup_path_fs):
        logger.critical(
            'dcfuzz cgroup not exists. make sure to run /init.sh first')
        terminate_dcfuzz()

    t = trees.Tree()
    p = os.path.join('/cpu', cgroup_path[1:], 'dcfuzz')
    CGROUP_ROOT = os.path.join(cgroup_path, 'dcfuzz')
    cpu_node = t.get_node_by_path(p)
    
    for fuzzer in FUZZERS:
        fuzzer_cpu_node = t.get_node_by_path(os.path.join(p, fuzzer))
        if not fuzzer_cpu_node:
            fuzzer_cpu_node = cpu_node.create_cgroup(fuzzer)
        cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us
        quota = int(cfs_period_us * (1))
        fuzzer_cpu_node.controller.cfs_quota_us = quota

    logger.info(f'main 201 - cgroup init end')
    return True


class SchedulingAlgorithm(metaclass=SingletonABCMeta):
    @abstractmethod
    def __init__(self, fuzzers, focus=None, one_core=False, N=1):
        pass

    @abstractmethod
    def run(self):
        pass

class Schedule_Base(SchedulingAlgorithm):
    def __init__(self,
                 fuzzers: List[str],
                 prep_time: int,
                 focus_time: int,
                 jobs: int = 1):
        self.fuzzers = fuzzers
        #self.rcFuzzers = rcFuzzers
        self.name = 'schedule_base'

        # to support multicore
        self.jobs = jobs

        self.round_num = 1
        self.round_start_time = 0
        self.first_round = True

        self.prep_fuzzers: List[Fuzzer] = []
        self.prep_time = prep_time
        self.prep_time_base = prep_time

        self.focus_time = focus_time
        self.focus_time_base = focus_time

        self.prep_time_round = 0
        self.focus_time_round = 0

        self.sync_time = 0

        # self.cov_before_collection: Coverage
        # self.cov_before_execution: Coverage

        # self.bitmap_contribution: BitmapContribution = {}
        # self.all_bitmap_contribution: BitmapContribution = {}  # will not reset
        # self.round_bitmap_contribution: Deque[BitmapContribution] = deque()
        # self.round_bitmap_intersection_contribution: Deque[
        #     BitmapContribution] = deque()
        # self.round_bitmap_distinct_contribution: Deque[
        #     BitmapContribution] = deque()

        self.picked_times: Dict[Fuzzer, int]
        self.diff_threshold = None

    def run_one(self, run_fuzzer):
        assert run_fuzzer in self.fuzzers
        for fuzzer in self.fuzzers:
            new_cpu = 1 if fuzzer == run_fuzzer else 0
            update_fuzzer_limit(fuzzer, new_cpu)
        logger.debug(f'single one: {run_fuzzer}')

    def pre_round(self):
        pass

    def one_round(self):
        pass

    def post_round(self):
        pass

    def main(self):
        pass
    
    def pre_run(self) -> bool:
        logger.info(f"main 910 - {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"main 920 - {self.name}: post_run")



class Schedule_Single(Schedule_Base):
    def __init__(self, fuzzers, single):
        self.fuzzers = fuzzers
        self.single = single
        self.name = f'Single_{single}'

    # def pre_round(self):      
    #     update_success = maybe_get_fuzzer_info(fuzzers=self.fuzzers)
    #     if not update_success:
    #         SLEEP = 10
    #         logger.info(
    #             f'main 019 - wait for all fuzzer having coverage, sleep {SLEEP} seconds')
    #         sleep(SLEEP)
    #         global START_TIME
    #         elasp = time.time() - START_TIME
    #         if elasp > 600:
    #             terminate_rcfuzz()
    #     return update_success

    # def post_round(self):
    #     fuzzer_info = get_fuzzer_info(self.fuzzers)
    #     fuzzer_info = compress_fuzzer_info(self.fuzzers, fuzzer_info)
    #     append_log('round', {'fuzzer_info': fuzzer_info})

    def one_round(self):
        logger.info(f'main 701 - one_round start')
        self.run_one(self.single)
        sleep(60)
    
    def main(self):
        logger.info(f'main 700 - single_fuzzer : {self.single}')
        while True:
            if is_end(): return
            #if not self.pre_round(): continue
            self.one_round()
        logger.info(f'main 709 - end')
            #self.post_round()

    def pre_run(self) -> bool:
        logger.info(f"main 710 - single fuzzer {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"main 720 - single fuzzer {self.name}: post_run")


# multi fuzzer 실행하기
class Schedule_DCFuzz(Schedule_Base):
    def __init__(self, fuzzers, prep_time=600, focus_time=600):
        super().__init__(fuzzers=fuzzers, prep_time=prep_time, focus_time=focus_time)
        self.name = f'RCFuzzer_{prep_time}_{focus_time}'        

        # 평가 정책이 어떻게 되는지 
        # thompson Sampling 은 어떻게 되는지
        # 정보를 어떻게 저장하고 비교할 것인지

        #self.find_new_round = False
        #self.policy_bitmap = policy.BitmapPolicy()
        #self.before_collection_fuzzer_info = empty_fuzzer_info(self.fuzzers)
        #self.diff_threshold = diff_threshold
        #self.focused_round = []
        #self.picked_times = {}        
    
    
    def prep(self):
        round_start_time = time.time()

        global OUTPUT
        logger.info(f'main 500 - start preparation phase')
        
        # set prep variable
        prep_fuzzers = self.fuzzers       
        prep_time = self.prep_time
        remain_time = prep_time
        prep_round = 1

        do_sync(self.fuzzers, OUTPUT)

        logger.info(f'main 501 - sync end')
        
        while remain_time > 0 :
            run_time = min(remain_time,30)

            for prep_fuzzer in prep_fuzzers:
                logger.info(f'main 502 - prep_fuzzer : {prep_fuzzer}, run time : {run_time}')
                self.run_one(prep_fuzzer)
                sleep(run_time)

            remain_time -= run_time
            prep_round +=1
            do_sync(self.fuzzers, OUTPUT)
        
        
        #do_sync(self.fuzzers, OUTPUT)

        # self.before_collection_fuzzer_info = fuzzer_info
        # logger.debug(f'before_fuzzer_info: {self.before_collection_fuzzer_info}')

        # collection_fuzzers = self.fuzzers
        # self.collection_fuzzers = collection_fuzzers

        # previous_bitmap = self.before_collection_fuzzer_info['global_bitmap'].count()
        # previous_unique_bug = self.before_collection_fuzzer_info['global_unique_bugs']['unique_bugs']

        # logger.info(f'main 900 -  collection start result(whole) - previous_bitmap : {previous_bitmap},  previous_unique_bug : {previous_unique_bug}')

        # self.collection_round_robin()
        
        # collection_end_time = time.time()
        # after_collection_fuzzer_info = get_fuzzer_info(self.fuzzers)

        # current_bitmap = after_collection_fuzzer_info['global_bitmap'].count()
        # current_unique_bug = after_collection_fuzzer_info['global_unique_bugs']['unique_bugs']

        # logger.info(f'main 901 - collection end result(whole) - previous_bitmap: {previous_bitmap}, current_bitmap: {current_bitmap}, previous_unique_bug : { previous_unique_bug}, current_unique_bug : { current_unique_bug}')

        # for fuzzer in FUZZERS:
        #     logger.info(f'main 902 - collection end result(each fuzzer) - fuzzer : { fuzzer }, fuzzer_success : { self.rcFuzzers[fuzzer].S }, fuzzer_fail : { self.rcFuzzers[fuzzer].F }, fuzzer_run_time : {self.rcFuzzers[fuzzer].total_runTime}, fuzzer_branch_difficulty : {self.rcFuzzers[fuzzer].diff}, fuzzer_threshold : {self.rcFuzzers[fuzzer].threshold}')
    


    def main(self):
        if is_end():return
        #if not self.pre_round():return
        logger.info(f'main 801 - prep phase start')
        self.prep()
        logger.info(f'main 802 - prep phase end')
        # while True:
        #     if is_end():return
        #     #if not self.pre_round():continue
        #     logger.info(f'main 503 - focus phase round {self.round_num} start')
        #     self.focus()
        #     logger.info(f'main 504 - focus phase round {self.round_num} end')
        #     #self.post_round()
        
    def pre_run(self) -> bool:
        logger.info(f"main 810 - {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"main 820 - {self.name}: post_run")



def main():
    global ARGS, TARGET, FUZZERS, OUTPUT, INPUT, TIMEOUT, PREP_TIME, FOCUS_TIME
    global START_TIME, LOG_DATETIME, LOG_FILE_NAME
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
    
    START_TIME = time.time()
    current_time = time.time()
    init()
    LOG['dcfuzz_args'] = ARGS.as_dict()  # remove Namespace
    LOG['dcfuzz_config'] = config
    LOG['start_time'] = current_time
    LOG['algorithm'] = None

    # setup cgroup
    init_cgroup()

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

        logger.info(f'main 005 - pause before')
        pause(fuzzer=fuzzer, jobs=1, input_dir=INPUT)
        logger.info(f'main 005.5 - pause after')
        

    LOG_DATETIME = f'{datetime.datetime.now():%Y-%m-%d-%H-%M-%S}'
    LOG_FILE_NAME = f'{TARGET}_{LOG_DATETIME}.json'

    # 결과들을 캡처하여 저장하는 백그라운드 스레드 영역으로 multi 진행할 때 필요
    # thread_fuzzer_log = threading.Thread(target=thread_update_fuzzer_log, kwargs={'fuzzers': FUZZERS}, daemon=True)
        
    # thread_fuzzer_log.start()
        
    # thread_health = threading.Thread(target=thread_health_check, daemon=True)
    # thread_health.start()

    scheduler = None
    algorithm = None

    fuzzerNum = len(FUZZERS) 

    if fuzzerNum == 1:
        logger.info(f'main 006 - single_fuzzer : {FUZZERS[0]}')
        scheduler = Schedule_Single(fuzzers=FUZZERS, single=FUZZERS[0])
        algorithm = FUZZERS[0]
    else: 
        logger.info(f'main 006 - multi_fuzzer : {FUZZERS}, PREP_TIME : {PREP_TIME}, FOCUS_TIME :{FOCUS_TIME} ')
        scheduler = Schedule_DCFuzz(fuzzers=FUZZERS, prep_time=PREP_TIME, focus_time=FOCUS_TIME)
        algorithm = 'dcfuzz'
    
    LOG['algorithm'] = algorithm

    RUNNING = True

    # thread_log = threading.Thread(target=thread_write_log, daemon=True)
    # thread_log.start()

    # # Timer to stop all fuzzers
    logger.info(f'main 007 - algorithm : {algorithm}, scheduler: {scheduler}')

    scheduler.run()

    # finish_path = os.path.join(OUTPUT, 'finish')
    # pathlib.Path(finish_path).touch(mode=0o666, exist_ok=True)
    # while not is_end_global():
    #     logger.info('main 039 - sleep to wait final coverage')
    #     time.sleep(300)

    LOG['end_time'] = time.time()

    write_log()
    logger.info(f'main 999 - end program')
    cleanup(0)


if __name__ == '__main__':
    main()
