import os
import re
import sys
from pathlib import Path
import shutil
import time
import logging
import subprocess
import peewee

from . import config as Config
from .evaluateDB import AFLGoSeed, WindRangerSeed, DAFLSeed, init_db

CONFIG = Config.CONFIG
SCORE_CONFIG = CONFIG['score_DAFL']
DAFL_CONFIG = CONFIG['fuzzer']['dafl']

logger = logging.getLogger('dcfuzz.evaluate')

# -----------------------------
# Args / Run
# -----------------------------
def gen_run_args(seed, output, program):
    global SCORE_CONFIG, DAFL_CONFIG, CONFIG
    logger.info("evaluator 100 - start gen_run_args")
    args = []
    command = SCORE_CONFIG['command']

    target = DAFL_CONFIG['target_root']
    target_root = os.path.join(target, program)

    target_config = CONFIG['target'][program]
    target_args = target_config['args']['default']
    logger.info(f"evaluator 101 - command : {command}, target_args : {target_args}, target_root : {target_root}")

    args += [command, '-i', seed, '-o', output]
    args += ['-m', 'none']
    args += ['-t', '10000+']
    args += ['-d']
    args += ['--', target_root]
    if target_args != '':
        args += target_args.split(' ')
    return args

def normalize_afl_seed_id(name: str) -> str:
    """
    Extract only 'id:XXXXXX' from AFL seed name.
    """
    base = os.path.basename(name)

    m = re.match(r"(id:\d+)", base)
    if not m:
        raise ValueError(f"Invalid AFL seed name: {name}")

    return m.group(1)

def extract_afl_seed_id(line: str) -> str:
    _, rest = line.split(",", 1)          
    base = os.path.basename(rest)         
    m = re.search(r"\bid:\d+\b", base)    
    if not m:
        raise ValueError(f"Cannot find seed id in line: {line}")
    return m.group(0)

def parse_score_file(path):
    parse_data = {}
    with open(path, "r") as f:
        lines = f.read().strip().splitlines()

    for line in lines[1:]:
        parts = line.split(",")

        prox_score = int(parts[-3])
        bitmap_size = int(parts[-1])

        filename_parts = parts[1:-3]
        
        name = extract_afl_seed_id(line)
        parse_data[name] = (prox_score, bitmap_size)
        logger.info(f"evaluator 222 - name : {name}, parse_data : {parse_data[name]}")

    return parse_data


def wait_for_file(path):
    wait_time = 0
    while not os.path.exists(path):
        wait_time += 1
        time.sleep(1)
        if wait_time == 600:
            logger.info('evaluator 666 - no exists')
            break


def cleanup_score_artifacts(score_file, snapshot_dir, score_workdir):
    """
    one-shot evaluator 전제:
    - score_workdir 는 매번 새로 만들고(run) 끝나면 통째로 삭제
    - snapshot_input 도 임시이므로 삭제
    - score_file(initial_seed_scores.txt)도 잔재 방지 위해 삭제
    - DB(sqlite)는 건드리지 않음
    """
    if os.path.exists(score_file):
        try:
            os.remove(score_file)
        except Exception:
            pass

    if os.path.exists(snapshot_dir):
        shutil.rmtree(snapshot_dir, ignore_errors=True)

    if os.path.exists(score_workdir):
        shutil.rmtree(score_workdir, ignore_errors=True)


def get_seed_model(fuzzer: str):
    f = fuzzer.lower()
    if f == "aflgo":
        return AFLGoSeed
    if f == "windranger":
        return WindRangerSeed
    if f == "dafl":
        return DAFLSeed
    raise ValueError(f"Unknown fuzzer: {fuzzer}")


# -----------------------------
# Snapshot: copy only "new" seeds for this fuzzer
# -----------------------------
def snapshot_dir_incremental(fuzzer: str, src_queue: str, dst_dir: str):
    logger.info(f'evaluator 003 - incremental snapshot: fuzzer={fuzzer}, src_queue={src_queue}, dst_dir={dst_dir}')

    SeedModel = get_seed_model(fuzzer)

    src = Path(src_queue)
    dst = Path(dst_dir)

    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)

    staged_names = []

    for p in src.iterdir():
        if not p.is_file():
            continue
        if p.name.startswith(".") or p.name == "README.txt":
            continue

        seed_id = normalize_afl_seed_id(p.name)

        if SeedModel.select().where(SeedModel.name == seed_id).exists():
            continue

        shutil.copy2(p, dst / p.name)
        staged_names.append(seed_id)

    logger.info(f"evaluator 004 - staged new seeds: {len(staged_names)}")
    return staged_names


def max_prox_from_db(fuzzer: str) -> int:
    SeedModel = get_seed_model(fuzzer)
    v = (SeedModel
         .select(peewee.fn.COALESCE(peewee.fn.MAX(SeedModel.prox_score), -1))
         .scalar())
    return int(v)


def extract_score(fuzzer, seed, output_dir, program):
    logger.info(f'evaluator 001 - fuzzer : {fuzzer}, seed : {seed}, output_dir : {output_dir}, program : {program}')

    seed_path = os.path.realpath(seed)
    output_path = os.path.realpath(output_dir)

    base_dir = "/home/dcfuzz"
    score_path = os.path.join(base_dir, "initial_seed_scores.txt")

    os.makedirs(output_path, exist_ok=True)

    db_path = os.path.join(output_path, f"{fuzzer}.sqlite")
    database = peewee.SqliteDatabase(db_path)
    init_db(database)

    snapshot_input = os.path.join(output_path, "input_snapshot")

    score_workdir = os.path.join(output_path, f"_score_run_{fuzzer}_{program}")

    # delete remain file or folder
    cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
    os.makedirs(score_workdir, exist_ok=True)

    staged_names = snapshot_dir_incremental(
        fuzzer=fuzzer,
        src_queue=seed_path,
        dst_dir=snapshot_input
    )

    if not staged_names:
        max_cached = max_prox_from_db(fuzzer)
        logger.info(f"evaluator 010 - no new seeds for {fuzzer}. return max_cached={max_cached}")
        cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
        return max_cached

    args = gen_run_args(seed=snapshot_input, output=score_workdir, program=program)
    logger.info(f'evaluator 002 - args : {args}')

    result = subprocess.run(
        args,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        logger.info(f"evaluator 9999 : afl-fuzz failed (rc={result.returncode})")
        logger.info(f"evaluator 6666 : stdout:\n{result.stdout}")
        logger.info(f"evaluator 6666 : stderr:\n{result.stderr}")

    wait_for_file(path=score_path)
    
    if not os.path.exists(score_path):
        max_cached = max_prox_from_db(fuzzer)
        logger.info(f"evaluator 011 - score file not created. return max_cached={max_cached}")
        cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)
        return max_cached

    name_to_score = parse_score_file(score_path)
    SeedModel = get_seed_model(fuzzer)
    with database.atomic():
        for name in staged_names:
            # logger.info(f"evaluator 013 - name : {name}")
            if name in name_to_score:
                prox, bmsz = name_to_score[name]
            else:
                prox, bmsz = -1, -1

            row, _ = SeedModel.get_or_create(name=name)
            row.prox_score = prox
            row.bitmap_size = bmsz
            row.save()

    # ✅ 정리: score 파일 + snapshot + score_workdir 삭제, DB는 유지
    cleanup_score_artifacts(score_file=score_path, snapshot_dir=snapshot_input, score_workdir=score_workdir)

    max_score = max_prox_from_db(fuzzer)
    logger.info(f"evaluator 020 - fuzzer={fuzzer} max_score(from DB)={max_score}")
    return max_score
