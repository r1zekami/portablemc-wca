import subprocess
import os
import argparse

parser = argparse.ArgumentParser(description='Import certificate into Java cacerts keystore.')
parser.add_argument('--crt', required=True, help='Path to the certificate file')
parser.add_argument('--jvm', required=True, help='Path to the JVM directory')
args = parser.parse_args()

cert_file = args.crt
jvm_path = args.jvm

keytool_path = os.path.join(jvm_path, 'bin', 'keytool.exe')
alias = os.path.splitext(os.path.basename(cert_file))[0]

if not os.path.exists(keytool_path):
    print(f"Err: keytool not found by {keytool_path}")
    exit(1)
if not os.path.exists(cert_file):
    print(f"Err: crt file not found by {cert_file}")
    exit(1)

storepass = "changeit"

command = [
    keytool_path,
    '-importcert',
    '-file', cert_file,
    '-cacerts',
    '-storepass', storepass,
    '-alias', alias,
    '-noprompt'
]

try:
    result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(f"Success")
except subprocess.CalledProcessError as e:
    print(f"Crt injecting error")