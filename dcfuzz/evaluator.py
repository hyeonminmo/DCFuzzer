import os
import sys
import pathlib
import shutil
import time
import logging
import subprocess

from . import config as Config


CONFIG = Config.CONFIG
SCORE_CONFIG = CONFIG['score_DAFL']
DAFL_CONFIG = CONFIG['fuzzer']['dafl']

logger = logging.getLogger('dcfuzz.evaluate')

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
        if seed_id == 0:
            seed_name = filename_parts[0]
            exec_time = 0
        else:
            seed_name = filename_parts[0]       
            exec_time = int(filename_parts[1]) 
            
        results[seed_id] = {
            "seedName": seed_name,
            "execTime": exec_time,
            "Prox_Score": prox_score,
            "Bitmap_Size": bitmap_size
        }
          
    return results

def wait_for_file(path):
    while not os.path.exists(path):
        time.sleep(0.1)
        
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

# max_score

def extract_score(fuzzer, seed, output_dir, program):
    logger.info(f'evaluator 001 - fuzzer : {fuzzer}, seed : {seed}, output_dir : {output_dir}, program : {program}')
    # example - fuzzer : aflgo, seed : /home/dcfuzz/output/swftophp-2016-9827/aflgo/queue, output_dir : /home/dcfuzz/output/swftophp-2016-9827/score, program : swftophp-2016-9827
    seed_path = os.path.realpath(seed)
    output_path = os.path.realpath(output_dir)
    base_dir = "/home/dcfuzz"

    args = gen_run_args(seed=seed_path, output=output_path, program=program)
    logger.info(f'evaluator 002 - args : {args}')
    
    result = subprocess.run(args,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    
    score_path = os.path.join(base_dir, "initial_seed_scores.txt")
    wait_for_file(path= score_path)
    results = parse_score_file(path = score_path)
    
    max_score = max(item["Prox_Score"] for item in results.values())
    
    # clean
    cleanup(score_dir=output_dir, score_file= score_path)
    
    return max_score
    







