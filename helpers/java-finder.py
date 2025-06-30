import shutil

def find_system_java():
    java_path = shutil.which("java")
    if java_path is None:
        raise RuntimeError("System Java not found in PATH. Please install Java or specify --jvm manually.")
    return java_path

print(find_system_java())

