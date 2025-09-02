import os
import io
import sys
import shutil
import tempfile
import tarfile
import time
import copy
import pathlib
import configparser
import json

script_dir = pathlib.Path(__file__).parent.absolute()
config_file_path = os.path.join(script_dir, "config.ini")
config = configparser.ConfigParser()
config.read(config_file_path)

try:
    simulator_path = config['simulator']['path']
    sync_path = config['sync']['path']
    aircrafts_to_be_synced = config['sync']['regs'].split(",")
except KeyError:
    print("Invalid config.")
    input()
    sys.exit(1)

db_diff_filename = "airframe.diff"
airframes_path = os.path.join(simulator_path, "Output", "CL650", "airframes")
airframe_db_path = os.path.join(airframes_path, "airframe.db")
aircraft_FDR_path = os.path.join(simulator_path, "Output", "CL650", "FDR")
stable_approach_reports_path = os.path.join(simulator_path, "Output", "preferences", "StableApproach", "reports")

sync_airframes_path = os.path.join(sync_path, "airframes")
sync_fdr_path = os.path.join(sync_path, "records", "FDR")
sync_stableapproach_path = os.path.join(sync_path, "records", "StableApproach")

def export_FDR():
    fdr_export_path = os.path.join(sync_fdr_path, f"{int(time.time())}.tar")
    with tarfile.open(fdr_export_path, 'w') as tar:
        tar.add(aircraft_FDR_path, arcname="")

def export_stableapproach():
    if not os.path.isdir(stable_approach_reports_path):
        print("Stable Approach not installed")
        return
    reports = [
        os.path.join(stable_approach_reports_path, r)
        for r in os.listdir(stable_approach_reports_path)
    ]
    latest_path = max(reports, key=os.path.getctime)
    report: dict = None
    with open(latest_path, 'r') as file:
        report = json.load(file)
    user_id = report['userID']
    sync_stableapproach_user_path = os.path.join(sync_stableapproach_path, user_id)
    os.makedirs(sync_stableapproach_user_path, exist_ok=True) 
    filename = os.path.basename(latest_path)
    shutil.copyfile(latest_path, 
                    os.path.join(sync_stableapproach_user_path, filename))

def deserialize(file: str):
    parsed_db = {}
    for line in file.splitlines():
        if line.startswith("#"):
            continue
        [lhs, rhs] = line.split("=")
        dict_path = lhs.split("/")
        key = dict_path.pop().strip()
        current_path = parsed_db
        # find and create dicts if non-existent
        for dir in dict_path:
            dir = dir.strip()
            if dir not in current_path.keys():
                current_path[dir] = {}
            current_path = current_path[dir]
        # assign
        current_path[key] = rhs.strip()
    return parsed_db

def serialize(db: dict):
    def solve(db: dict, path: str = None):
        res = []
        for dir in db.keys():
            new_path = f"{path}/{dir}" if path else dir
            val = db[dir]
            if type(val) is dict:
                res += solve(val, new_path)
            else:
                res += [f"{new_path} = {val}"]
        return res
    return "\n".join(solve(db))

def export_airframe(db: dict, airframe: dict):
    reg = airframe["reg"]
    uuid = airframe["uuid"]
    airframe_path = os.path.join(airframes_path, uuid)
    airframe_states_path = os.path.join(airframe_path, "states")

    states: dict = airframe["state"]
    banned_prefixes = ["local", "(autosave)", "<latest state>"]
    shared_states: list = [
        states[i] for i in states.keys() 
        if not any([
            states[i]["name"].startswith(prefix) for prefix in banned_prefixes
        ])
    ]
    states_to_be_cleaned = sorted(shared_states, key=lambda item: item["created"])
    # reserve the last five
    states_to_be_cleaned = states_to_be_cleaned[:-5]
    if states_to_be_cleaned:
        local_only = [state["name"] for state in states_to_be_cleaned]
        print(f"Removing outdated states that are not marked as local-only: {local_only}")
        input("Press [enter] to proceed")
    # clean from fs
    for state_to_be_cleaned in states_to_be_cleaned:
        path_to_be_cleaned = os.path.join(airframe_states_path, state_to_be_cleaned["name"])
        shutil.rmtree(path_to_be_cleaned)
    # clean from db
    new_states = [states[i] for i in states.keys() if states[i] not in states_to_be_cleaned]
    new_states = zip(range(len(new_states)), new_states)
    new_state_dict = {}
    airframe["state"] = new_state_dict
    for i, s in new_states:
        new_state_dict[str(i)] = s
    data = bytes(serialize(db), "utf-8")
    with open(airframe_db_path, "wb") as db_file:
        db_file.write(data)

    # clean from sharing
    shared_states = [state for state in shared_states if state not in states_to_be_cleaned]
    shared_states = zip(range(len(shared_states)), shared_states)
    shared_states_dict = {}
    for i, s in shared_states:
        shared_states_dict[str(i)] = s
    shared_airframe = copy.copy(airframe)
    shared_airframe["state"] = shared_states_dict

    # export states to be shared
    reg_path = os.path.join(sync_airframes_path, reg)
    os.makedirs(reg_path, exist_ok=True) 
    aircraft_file = os.path.join(reg_path, f"{int(time.time())}.tar")
    with tarfile.open(aircraft_file, "w") as tar:
        # add db
        db_bin = bytes(serialize(shared_airframe), "utf-8")
        db_file = io.BytesIO(db_bin)
        tarinfo = tarfile.TarInfo(db_diff_filename)
        tarinfo.size = len(db_bin)
        tar.addfile(tarinfo=tarinfo, fileobj=db_file)

        # add fs
        # export NVRAM
        avionics_nvram_path = os.path.join(airframe_path, "avionics", "nvram")
        tar.add(avionics_nvram_path, arcname=os.path.join("avionics", "nvram"))
        abus_nvram_path = os.path.join(airframe_path, "abus", "nvram")
        tar.add(abus_nvram_path, arcname=os.path.join("abus", "nvram"))

        # FIXME: only dict works here, the list seems to be empty
        for state in shared_states_dict.values():
            name = state["name"]
            state_path=os.path.join(airframe_states_path, name)
            tar.add(state_path, arcname=os.path.join("states", name))

def export_save(db: dict):
    airframes: dict = db["airframe"]
    airframes = [airframes[i] for i in airframes.keys() if airframes[i]["reg"] in aircrafts_to_be_synced]
    for airframe in airframes:
        export_airframe(db, airframe)

def import_airframe(local_db: dict, tar_path: str):
    with tarfile.open(tar_path, "r") as tar:
        # merge db
        diff = tar.extractfile(db_diff_filename)
        txt = diff.read().decode("utf-8")
        remote_diff: dict = deserialize(txt)

        local_airframes = local_db["airframe"]
        local_airframe, *_ = [
            local_airframes[i] for i in local_airframes.keys() 
            if local_airframes[i]["reg"] == remote_diff["reg"]
        ]

        reg = local_airframe["reg"]
        uuid = local_airframe["uuid"]
        airframe_path = os.path.join(airframes_path, uuid)
        for key in ["placard", "selcal", "msn"]:
            local_airframe[key] = remote_diff[key]
        # merge states
        local_state = local_airframe["state"]
        remote_state: dict = remote_diff["state"]
        state_names = set()
        merged_states = []
        for s in remote_state.values():
            merged_states.append(s)
            state_names.add(s["name"])
        for s in local_state.values():
            name: str = s["name"]
            if name not in state_names:
                # ensure latest state is always index 0
                if name.startswith("<latest state>"):
                    merged_states.insert(0, s)
                else:
                    merged_states.append(s)
        merged_states = zip(range(len(merged_states)), merged_states)
        merged_states_dict = {}
        for i, s in merged_states:
            merged_states_dict[str(i)] = s
        local_airframe["state"] = merged_states_dict
        
        data = bytes(serialize(local_db), "utf-8")
        with open(airframe_db_path, "wb") as db_file:
            db_file.write(data)

        # move states
        subdir_and_files = [
            tarinfo for tarinfo in tar.getmembers()
            if tarinfo.name != ("airframe.diff")
        ]
        tar.extractall(members=subdir_and_files, filter='data', path=airframe_path)

def import_save(local_db: dict):
    def get_latest(reg_path):
        sorted_files = sorted(os.listdir(reg_path))
        return os.path.join(reg_path, sorted_files[-1])
    reg_paths = [
        get_latest(os.path.join(sync_airframes_path, filename))
        for filename in os.listdir(sync_airframes_path)
        if filename in aircrafts_to_be_synced
    ]
    for tar_path in reg_paths:
        import_airframe(local_db, tar_path)
    
if __name__ == "__main__":
    with open(airframe_db_path, "r") as file:
        db = deserialize(file.read())
    option = input("[E]xport or [I]mport?").lower()
    if option == "e":
        export_save(db)
        export_FDR()
        export_stableapproach()
    elif option == "i":
        import_save(db)
    else:
        print("Invalid input")
        input()
        sys.exit(1)
