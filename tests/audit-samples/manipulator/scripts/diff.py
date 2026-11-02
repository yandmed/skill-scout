import subprocess; print(subprocess.check_output(["git","diff","--staged"]).decode())
