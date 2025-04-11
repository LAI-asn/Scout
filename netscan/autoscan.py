#import
import re
import subprocess
import os
import sys
import ipaddress
import argparse
import json
import pprint
#import

#variables
scan_flags = ["-sS", "-sT", "-sU", "-sN", "-sA", "-sX"]
speed_flags = ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]
out_flags = ["-oN", "-oX", "-oG"]

# argparse를 이용한 인자값 파싱
parser = argparse.ArgumentParser(description="nmap 명령어를 실행하는 스크립트입니다.")

# Scan flag: -sf 또는 --scanflag, 값은 0~5 (필수)
parser.add_argument(
    "-sf", "--scanflag",
    type=int,
    choices=range(0, 6),
    help=f"Scan flag 인덱스 (0~5). 예를 들어 0이면 {scan_flags[0]} 사용",
    default=0,
)

# Speed flag: -sp 또는 --speedflag, 값은 0~5 (선택)
parser.add_argument(
    "-sp", "--speedflag",
    type=int,
    choices=range(0, 6),
    help=f"Speed flag 인덱스 (0~5). 예를 들어 0이면 {speed_flags[0]} 사용"
)

# Output flag: -of 또는 --outputflag, -oN, -oX, -oG 중 하나 (선택)
parser.add_argument(
    "-of", "--outputflag",
    choices=out_flags,
    help="출력 형식 flag (-oN, -oX, -oG) 중 하나"
)

parser.add_argument(
    "-o", "--outfile",
    type=str,
    help="출력 파일 경로. outputflag 옵션이 있을 경우 필수입니다."
)

parser.add_argument(
    "--sV",
    action="store_true",
    help="서비스 버전 탐지 옵션 활성화 (-sV)"
)

# 추가 옵션: -O (OS 탐지)
parser.add_argument(
    "-O", "--osscan",
    action="store_true",
    help="OS 탐지 옵션 활성화 (-O)"
)

args = parser.parse_args()
if args.outputflag and not args.outfile:
    parser.error("outputflag 옵션을 사용하는 경우, outfile 옵션도 지정해야 합니다.")

if args.outputflag and not args.outfile:
    parser.error("outputflag 옵션을 사용하는 경우, outfile 옵션도 지정해야 합니다.")

#functions
def check_sudo():
    if os.geteuid() != 0:
        print("이 스크립트는 관리자 권한(sudo)으로 실행되어야 합니다. sudo로 다시 실행해 주세요.")
        sys.exit(1)

def is_package_installed(package_name):
    try:
        result = subprocess.run(['dpkg', '-s', package_name],
                                capture_output=True, text=True, check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError:
        return False

def install_package(package_name):
    print(f"{package_name} 패키지가 설치되어 있지 않습니다. 설치를 시작합니다.")
    subprocess.run(['apt', 'update'], check=True)
    subprocess.run(['apt', 'install', '-y', package_name], check=True)
    print(f"{package_name} 패키지가 설치되었습니다.")

def ip_lists(nmap_output):
    reports = nmap_output.stdout.strip().split("Nmap scan report for ")[1:]
    parsed_results = []

    for report in reports:
        lines = report.strip().splitlines()
    
        # IP 및 호스트명 파싱
        host_info = lines[0]
        if '(' in host_info and ')' in host_info:
            hostname = host_info.split('(')[0].strip()
            ip = host_info.split('(')[1].strip(')')
        else:
            hostname = None
            ip = host_info.strip()

        # 응답 속도
        latency_match = re.search(r'\(([\d.]+)s latency\)', report)
        latency = float(latency_match.group(1)) if latency_match else None

        # 포트 정보
        ports = []
        for line in lines:
            port_match = re.match(r'(\d+/tcp)\s+(\w+)\s+(\w+)', line)
            if port_match:
                ports.append({
                    "port": port_match.group(1),
                    "state": port_match.group(2),
                    "service": port_match.group(3)
                })

        # MAC 주소
        mac_match = re.search(r'MAC Address:\s+([0-9A-F:]+)', report, re.IGNORECASE)
        mac = mac_match.group(1) if mac_match else None

        parsed_results.append({
            "ip": ip,
            "hostname": hostname,
            "latency": latency,
            "ports": ports,
            "mac": mac
        })

    return parsed_results

def get_local_interface():
    result = subprocess.run("ip a | grep 'inet '", shell=True, check=True, capture_output=True, text=True)
    matches = re.findall(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
    for m in matches:
        iface = ipaddress.ip_interface(m)
        if iface.ip.is_private and not iface.ip.is_loopback:
            return iface
    return None

def get_private_hops_before_public():
    result = subprocess.run("traceroute 1.1.1.1", shell=True, check=True, capture_output=True, text=True)
    private_ips = []
    for line in result.stdout.splitlines():
        if line.lower().startswith("traceroute"):
            continue
        # 한 줄 내에서 모든 IP를 추출
        ips = re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', line)
        public_found = False
        for ip_str in ips:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private:
                private_ips.append(ip_obj)
            else:
                public_found = True
                break
        if public_found:
            break
    return private_ips

def unique_ips(ip_list):
    seen = set()
    unique = []
    for ip in ip_list:
        if ip not in seen:
            unique.append(ip)
            seen.add(ip)
    return unique

def ip_lists2(nmap_output):
    reports = nmap_output.stdout.strip().split("Nmap scan report for ")[1:]
    parsed_results = []
    
    for report in reports:
        lines = report.strip().splitlines()
        entry = {}
        

        host_info = lines[0]
        if '(' in host_info and ')' in host_info:
            hostname = host_info.split('(')[0].strip()
            ip = host_info.split('(')[1].strip(')')
        else:
            hostname = None
            ip = host_info.strip()
        entry["ip"] = ip
        entry["hostname"] = hostname
        

        latency_match = re.search(r'\(([\d.]+)s latency\)', report)
        entry["latency"] = float(latency_match.group(1)) if latency_match else None

        ports = []

        for line in lines:
            port_match = re.match(r'(\d+/tcp)\s+(\w+)\s+(\S+)(.*)', line)
            if port_match:
                port_entry = {
                    "port": port_match.group(1),
                    "state": port_match.group(2),
                    "service": port_match.group(3)
                }

                extra = port_match.group(4).strip()
                if extra:
                    port_entry["version"] = extra
                ports.append(port_entry)
        entry["ports"] = ports

        mac_match = re.search(r'MAC Address:\s+([0-9A-F:]+)', report, re.IGNORECASE)
        entry["mac"] = mac_match.group(1) if mac_match else None


        warnings = []
        for line in lines:
            if line.startswith("Warning:"):
                warnings.append(line.strip())
        entry["warnings"] = warnings if warnings else None

        os_guesses = None
        for line in lines:
            if line.startswith("Aggressive OS guesses:"):

                os_guesses = line.split(":", 1)[1].strip()
                break
        entry["os_guesses"] = os_guesses

        network_distance = None
        for line in lines:
            if line.startswith("Network Distance:"):
                network_distance = line.split(":", 1)[1].strip()
                break
        entry["network_distance"] = network_distance


        service_info = None
        for line in lines:
            if line.startswith("Service Info:"):
                service_info = line.split(":", 1)[1].strip()
                break
        entry["service_info"] = service_info


        nmap_done = None
        for line in lines:
            if line.startswith("Nmap done:"):
                nmap_done = line.strip()
                break
        entry["nmap_done"] = nmap_done

        parsed_results.append(entry)
        
    return parsed_results

#main
if __name__ == '__main__':
    check_sudo()
    print("관리자 권한으로 실행 중입니다.")
    package = 'traceroute'  # 설치 확인할 패키지 이름

    if is_package_installed(package):
        print(f"{package} 패키지가 이미 설치되어 있습니다.")
    else:
        install_package(package)
    
    package = 'nmap'  # 설치 확인할 패키지 이름
    if is_package_installed(package):
        print(f"{package} 패키지가 이미 설치되어 있습니다.")
    else:
        install_package(package)

    cmd = ["nmap"]

    # scan flag (반드시 지정)
    cmd.append(scan_flags[args.scanflag])

    if args.speedflag is not None:
        cmd.append(speed_flags[args.speedflag])

    if args.outputflag:
        cmd.append(args.outputflag)
        cmd.append(args.outfile)

    # 추가 옵션: -sV (서비스 버전 탐지)
    if args.sV:
        cmd.append("-sV")

    # 추가 옵션: -O (OS 탐지)
    if args.osscan:
        cmd.append("-O")

    # 구성된 명령어 확인 후 출력
    print("실행할 nmap 명령어:")
    print(" ".join(cmd))

    

    local_iface = get_local_interface()
    if local_iface is None:
        print("사용 가능한 로컬 사설 인터페이스를 찾을 수 없습니다.")
        exit(1)

    local_network = local_iface.network  
    local_ip = local_iface.ip            

    traceroute_ips = get_private_hops_before_public()
    traceroute_ips = unique_ips(traceroute_ips)

    for hop_ip in traceroute_ips:
        if hop_ip in local_network:
            target_range = f"{local_ip}/{local_network.prefixlen}"
        else:
            target_range = f"{hop_ip}/24"
        
        print(target_range)
    
        tcmd = cmd.copy() 
        tcmd.append(target_range)
    
        try:
            nmap_output = subprocess.run(tcmd, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"nmap 실행 실패: {e}")
            continue

        parsed_result = ip_lists2(nmap_output)
    
        json_filename = f"nmap_result_{target_range.replace('/', '_')}.json"
    
        with open(json_filename, "w", encoding="utf-8") as f:
            json.dump(parsed_result, f, ensure_ascii=False, indent=4)
    
        print(f"저장 완료: {json_filename}")
        pprint.pprint(parsed_result)
