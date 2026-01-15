import os
import sys
from pathlib import Path
import shutil
import time
import logging
import subprocess
import peewee

from . import config as Config
from .evaluateDB import AFLGoSeed, WindRangerSeed, DAFLSeed

CONFIG = Config.CONFIG
SCORE_CONFIG = CONFIG['score_DAFL']
DAFL_CONFIG = CONFIG['fuzzer']['dafl']

logger = logging.getLogger('dcfuzz.evaluate')

# -----------------------------
# Args / Run
# -----------------------------
def gen_run_args(seed, output, program):
    global SCORE_CONFIG, DAFL_CONFIG, CONFIG
    logger.info(f"evaluator 100 - start gen_run_args")
    args =[]
    command = SCORE_CONFIG['command']
    
    target = DAFL_CONFIG['target_root']
    target_root = os.path.join(target, program)

    target_config = CONFIG['target'][program]
    target_args = target_config['args']['default']
    logger.info(f"evaluator 101 - command : {command},  target_args : {target_args}, target_root : {target_root}")

    args += [command, '-i', seed, '-o', output]
    args += ['-m', 'none']
    args += ['-t', '10000+']
    args += ['-d']
    args += ['--', target_root]
    if not target_args == '':
        args += target_args.split(' ')
    return args

def parse_score_file(path):
    results = {}
    with open(path, "r") as f:
        lines = f.read().strip().splitlines()
    
    for line in lines[1:]:
        parts = line.split(",")
        seed_id = int(parts[0])
        prox_score = int(parts[-3])
        exec_us = int(parts[-2])
        bitmap_size = int(parts[-1])

        filename_parts = parts[1:-3]
        # if seed_id == 0:
        #     seed_name = filename_parts[0]
        #     exec_time = 0
        # else:
        #     seed_name = filename_parts[0]       
        #     exec_time = int(filename_parts[1]) 
            
        results[seed_id] = {
            "filename": filename_parts,
            "Prox_Score": prox_score,
            "Bitmap_Size": bitmap_size
        }
    return results

def wait_for_file(path):
    wait_time = 0 
    while not os.path.exists(path):
        wait_time+=1
        time.sleep(1)
        if wait_time == 600:
            logger.info(f'evaluator 666 - no exists')
            break
        
        
def cleanup(score_dir, score_file):
    if os.path.exists(score_file):
        os.remove(score_file)
    
    if not os.path.exists(score_dir):
        return

    for item in os.listdir(score_dir):
        path = os.path.join(score_dir, item)

        if os.path.isfile(path) or os.path.islink(path):
            os.remove(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)

def snapshot_dir(src_queue: str, dst_dir: str):
    logger.info(f'evaluator 003 -  src_queue : {src_queue}, dst_dir:{dst_dir}')
    src = Path(src_queue)
    dst = Path(dst_dir)
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    for p in src.iterdir():
        if p.is_file():
            shutil.copy2(p, dst / p.name)


def extract_score(fuzzer, seed, output_dir, program):
    logger.info(f'evaluator 001 - fuzzer : {fuzzer}, seed : {seed}, output_dir : {output_dir}, program : {program}')
    # example - fuzzer : aflgo, seed : /home/dcfuzz/output/swftophp-2016-9827/aflgo/queue, output_dir : /home/dcfuzz/output/swftophp-2016-9827/score, program : swftophp-2016-9827
    seed_path = os.path.realpath(seed)
    output_path = os.path.realpath(output_dir)
    base_dir = "/home/dcfuzz"
    snapshot_input = os.path.join(output_path, "input_snapshot")

    snapshot_dir(src_queue=seed_path, dst_dir=snapshot_input)

    args = gen_run_args(seed=snapshot_input, output=output_path, program=program)
    logger.info(f'evaluator 002 - args : {args}')
    
    # result = subprocess.run(args,
    #                         stdin=subprocess.DEVNULL,
    #                         stdout=subprocess.DEVNULL,
    #                         stderr=subprocess.DEVNULL)
    
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if result.returncode != 0:
        logger.info(f"evaluator 9999 : afl-fuzz failed")
        logger.info(f"evaluator 6666 : stdout:\n{result.stdout}")
        logger.info(f"evaluator 6666 : stderr:\n{result.stderr}")
    
    score_path = os.path.join(base_dir, "initial_seed_scores.txt")
    wait_for_file(path= score_path)
    results = parse_score_file(path = score_path)
    
    max_score = max(item["Prox_Score"] for item in results.values())
    
    # clean
    cleanup(score_dir=output_dir, score_file= score_path)
    
    return max_score
    







