import os
import subprocess


def show_log(commit_id):
    # AI-prone: shell=True with interpolation
    subprocess.run(f"git log {commit_id}", shell=True)


def remove_file(path):
    # AI-prone: os.system + concat
    os.system("rm -rf " + path)
