import asyncio
import keyring
import json
import webbrowser
import httpx
import socket
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.common.security import generate_token
from http.server import HTTPServer, BaseHTTPRequestHandler
from webdav3.client import Client as WebDavClient
from pathlib import PurePath, Path
from urllib.parse import urlparse, urljoin
import posixpath
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

CLIENT_ID = 'HV8vsMU3NzbbH3oG1iY5V7xnbHHoVcxJIq8FbOUP'
SCOPE = 'openid nextcloud offline_access'
CALLBACK_URL = 'http://127.0.0.1'
APP_ID = "app.mzt.dcars-client"
OPENID_CONF = httpx.get("https://sso.mzt.app/application/o/dcars-client/.well-known/openid-configuration").json()

script_dir = pathlib.Path(__file__).parent.absolute()
config_file_path = os.path.join(script_dir, "config.ini")
config = configparser.ConfigParser()
config.read(config_file_path)
sync_path = "/"

try:
    simulator_path = config['simulator']['path']
    aircrafts_to_be_synced = config['sync']['regs'].split(",")
except KeyError:
    if not Path(config_file_path).is_file():
        shutil.copy(os.path.join(script_dir, "config.ini.sample"), config_file_path)
    print("Invalid config.")
    print(f"Please edit your config file at {config_file_path}")
    input()
    sys.exit(1)

db_diff_filename = "airframe.diff"
airframes_path = os.path.join(simulator_path, "Output", "CL650", "airframes")
airframe_db_path = os.path.join(airframes_path, "airframe.db")
aircraft_FDR_path = os.path.join(simulator_path, "Output", "CL650", "FDR")
aircraft_HLIS_path = os.path.join(simulator_path, "Output", "CL650", "HLIS")
stable_approach_reports_path = os.path.join(simulator_path, "Output", "preferences", "StableApproach", "reports")

sync_airframes_path = posixpath.join(sync_path, "airframes")
sync_fdr_path = posixpath.join(sync_path, "records", "FDR")
sync_HLIS_path = posixpath.join(sync_path, "records", "HLIS")
sync_stableapproach_path = posixpath.join(sync_path, "records", "StableApproach")

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

def make_handler(app):
    class CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            app.captured_url = self.path
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"Login successful! You can close self window.")
    return CallbackHandler

def make_token_updater(app):
    async def update_token_in_keyring(token, refresh_token=None, access_token=None):
        sub = app.sub
        if not sub:
            print("This should be impossible")
            return
        keyring.set_password(APP_ID, sub, json.dumps(token))
        if app.webdav_client:
            app.webdav_client.session.headers.update({
                "Authorization": f"Bearer {token['access_token']}"
            })
        print("Token refreshed and WebDAV headers updated!")
    return update_token_in_keyring

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Binding to port 0 tells the OS to assign a free port
        s.bind(('127.0.0.1', 0))
        # Return the actual port number assigned
        return s.getsockname()[1]

class App:

    def __init__(self):
        self.oauth_client = None
        self.webdav_client = None
        self.sub = None


    async def export_FDR(self):
        fdr_export_path = posixpath.join(sync_fdr_path, f"{int(time.time())}.tar")
        temp_file = tempfile.NamedTemporaryFile()
        with tarfile.open(temp_file.name, 'w') as tar:
            tar.add(aircraft_FDR_path, arcname="")
        # TODO: async this
        self.webdav_client.upload(fdr_export_path, temp_file.name)

    async def export_HLIS(self):
        hlis_export_path = posixpath.join(sync_HLIS_path, f"{int(time.time())}.tar")
        temp_file = tempfile.NamedTemporaryFile()
        with tarfile.open(temp_file.name, 'w') as tar:
            tar.add(aircraft_HLIS_path, arcname="")
        # TODO: async this
        self.webdav_client.upload(hlis_export_path, temp_file.name)

    async def export_stableapproach(self):
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
        sync_stableapproach_user_path = posixpath.join(sync_stableapproach_path, user_id)
        self.webdav_client.mkdir(sync_stableapproach_user_path)
        filename = os.path.basename(latest_path)
        remote_path = posixpath.join(sync_stableapproach_user_path, filename)
        # TODO: async this
        self.webdav_client.upload(remote_path, latest_path)

    async def export_airframe(self, db: dict, airframe: dict):
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
        reg_path = posixpath.join(sync_airframes_path, reg)
        #os.makedirs(reg_path, exist_ok=True) 
        self.webdav_client.mkdir(reg_path)
        aircraft_file_path = posixpath.join(reg_path, f"{int(time.time())}.tar")
        temp_file = tempfile.NamedTemporaryFile()
        with tarfile.open(temp_file.name, "w") as tar:
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
        # TODO: async this
        self.webdav_client.upload(aircraft_file_path, temp_file.name)

    async def export_save(self, db: dict):
        airframes: dict = db["airframe"]
        airframes = [airframes[i] for i in airframes.keys() if airframes[i]["reg"] in aircrafts_to_be_synced]
        for airframe in airframes:
            await self.export_airframe(db, airframe)

    async def import_airframe(self, local_db: dict, tar_path: str):
        temp_file = tempfile.NamedTemporaryFile()
        # TODO: async
        self.webdav_client.download(tar_path, temp_file.name)
        with tarfile.open(temp_file.name, "r") as tar:
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

    async def import_save(self, local_db: dict):
        def get_base_dir(input_url):
            parsed_url = urlparse(input_url)
            path = parsed_url.path
            p = PurePath(path)
            if p.name:
                return p.name
            else:
                return p.parent.name
        def get_latest(reg_path):
            saves = filter(lambda x: x.endswith(".tar"), self.webdav_client.list(reg_path))
            sorted_files = sorted(saves)
            return posixpath.join(reg_path, sorted_files[-1])
        def check_to_be_synced(file_metadata):
            path = file_metadata['path']
            reg = get_base_dir(path)
            return reg in aircrafts_to_be_synced
        reg_paths = [
            get_latest(posixpath.join(sync_airframes_path, get_base_dir(file['path'])))
            for file in self.webdav_client.list(sync_airframes_path, get_info=True)
            if check_to_be_synced(file)
        ]
        for tar_path in reg_paths:
            await self.import_airframe(local_db, tar_path)


    def retrieve_credentials(self):
        credentials = keyring.get_credential(APP_ID, username=None)
        if not credentials:
            return None
        self.sub = credentials.username
        return json.loads(credentials.password)

    def init_webdav(self):
        options = {
         'webdav_hostname': f"https://nextcloud.mzt.app/remote.php/dav/files/{self.sub}/company-shared/",
        }
        self.webdav_client = WebDavClient(options)

    async def refresh_token(self):
        try:
            await self.oauth_client.refresh_token()
        except:
            await self.logout(False)
            await self.login()

    async def login(self):
        token_endpoint = OPENID_CONF['token_endpoint']
        authorization_endpoint = OPENID_CONF['authorization_endpoint']
        port = find_free_port()
        token_updater = make_token_updater(self)

        self.oauth_client = AsyncOAuth2Client(client_id=CLIENT_ID, 
                                            scope=SCOPE,
                                            token=self.retrieve_credentials(),
                                            authorization_endpoint=authorization_endpoint, 
                                            token_endpoint=token_endpoint, 
                                            revocation_endpoint=OPENID_CONF['revocation_endpoint'],
                                            update_token=token_updater,
                                            redirect_uri=f"{CALLBACK_URL}:{port}", 
                                            code_challenge_method='S256')
        if not self.sub:
            code_verifier = generate_token(48)
            authorization_url, state = self.oauth_client.create_authorization_url(authorization_endpoint, code_verifier=code_verifier)
            handler = make_handler(self)
            server = HTTPServer(('127.0.0.1', port), handler)
            webbrowser.open(authorization_url)
            server.handle_request()
            server.server_close()
            token = await self.oauth_client.fetch_token(token_endpoint, 
                                                        authorization_response=f"{CALLBACK_URL}:{port}{self.captured_url}", 
                                                        code_verifier=code_verifier)
            userinfo = await self.oauth_client.get(OPENID_CONF['userinfo_endpoint'])
            self.sub = userinfo.json()['sub']
            self.init_webdav()
            await token_updater(self.oauth_client.token)
        else:
            self.init_webdav()
            await self.refresh_token()

    async def logout(self, prompt=True):
        if self.sub:
            keyring.delete_password(APP_ID, self.sub)
            await self.oauth_client.revoke_token(OPENID_CONF['revocation_endpoint'], 
                                                 token=self.oauth_client.token['refresh_token'])
            self.sub = None
            if prompt:
                webbrowser.open(OPENID_CONF['end_session_endpoint'])

async def main():
    option = input("[E]xport or [I]mport?").lower()

    with open(airframe_db_path, "r") as file:
        db = deserialize(file.read())

    app = App()
    await app.login()
    # FIXME: check and refresh token before each webdav call
    if option == "e":
        await app.export_save(db)
        await app.export_FDR()
        await app.export_HLIS()
        await app.export_stableapproach()
    elif option == "i":
        await app.import_save(db)
    else:
        print("Invalid input")
        input()
        sys.exit(1)
    await app.testwebdav()
    #await app.logout()

if __name__ == "__main__":
    asyncio.run(main())
