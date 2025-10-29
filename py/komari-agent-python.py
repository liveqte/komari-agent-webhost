#!/usr/bin/env python3

#
# komari-agent-python by liming2038
# 基础原则：不是有贡献就可以对普通用户指指点点，普通用户使用开源项目也有平等发声权力，不能打着维护原作者的旗号来贬低他人，远离饭圈文化。
# 在平等、互相尊重基础上的使用本项目。
#

import asyncio
import json
import os
import platform
import sys
import time
import subprocess
import socket
import aiohttp
import websockets
import psutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import pty
import select

class Logger:
    """日志处理器"""
    _log_level = 0  # 0=关闭Debug日志, 1=基本信息, 2=WebSocket传输，3=终端日志，4网络统计日志，5磁盘统计日志
    
    @classmethod
    def set_log_level(cls, level: int):
        """设置日志级别"""
        cls._log_level = level
    
    @classmethod
    def _log(cls, message: str, level: str = "INFO"):
        """基础日志方法"""
        if cls._log_level == 0 and level != "ERROR":
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}"
        print(log_message)
        
        if level == "ERROR":
            print(log_message, file=sys.stderr)
    
    @classmethod
    def debug(cls, message: str, debug_level: int = 1):
        """调试日志"""
        if cls._log_level == debug_level:
            cls._log(message, "DEBUG")
    
    @classmethod
    def info(cls, message: str):
        """信息日志"""
        cls._log(message, "INFO")
    
    @classmethod
    def warning(cls, message: str):
        """警告日志"""
        cls._log(message, "WARNING")
    
    @classmethod
    def error(cls, message: str):
        """错误日志"""
        cls._log(message, "ERROR")

class SystemInfoCollector:
    """系统信息收集器"""
    
    VERSION = "komari-agent-python-1.0.0"
    
    def __init__(self):
        self.last_network_stats = {'rx': 0, 'tx': 0}
        self.total_network_up = 0
        self.total_network_down = 0
        self.last_network_time = time.time()
        self._cpu_initialized = False
        self._cpu_init_lock = asyncio.Lock()
    
    async def get_basic_info(self) -> Dict[str, Any]:
        """获取基础系统信息"""
        dist_info = self._get_linux_distribution()
        
        # 异步获取 IP 地址
        ipv4, ipv6 = await asyncio.gather(
            self._get_public_ip_v4(),
            self._get_public_ip_v6(),
            return_exceptions=True
        )
        
        # 处理异常情况
        ipv4 = ipv4 if not isinstance(ipv4, Exception) else None
        ipv6 = ipv6 if not isinstance(ipv6, Exception) else None
        
        if isinstance(ipv4, Exception):
            Logger.debug(f"获取 IPv4 失败: {ipv4}", 1)
            ipv4 = None
        if isinstance(ipv6, Exception):
            Logger.debug(f"获取 IPv6 失败: {ipv6}", 1)
            ipv6 = None
        
        os_name = f"{dist_info['name']} {dist_info['version']}" if dist_info['name'] != 'Unknown' else platform.system()
        
        info = {
            "arch": platform.machine(),
            "cpu_cores": psutil.cpu_count(),
            "cpu_name": self._get_cpu_name(),
            "disk_total": await self._get_disk_total(),
            "gpu_name": "",  # Python 暂不支持 GPU 检测
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mem_total": psutil.virtual_memory().total,  # 字节单位
            "os": os_name,
            "kernel_version": platform.release(),
            "swap_total": psutil.swap_memory().total,  # 字节单位
            "version": self.VERSION,
            "virtualization": self._get_virtualization()
        }
        
        Logger.debug(f"基础信息数据: {json.dumps(info, indent=2)}", 1)
        return info
    
    async def get_realtime_info(self) -> Dict[str, Any]:
        """获取实时监控信息"""
        cpu_usage = await self._get_cpu_usage()
        network_stats = await self._get_network_stats()
        memory_info = await self._get_memory_info()
        disk_info = await self._get_disk_info()
        
        info = {
            "cpu": {
                "usage": cpu_usage
            },
            "ram": {
                "total": memory_info["ram_total"],    # 字节
                "used": memory_info["ram_used"]       # 字节
            },
            "swap": {
                "total": memory_info["swap_total"],   # 字节
                "used": memory_info["swap_used"]      # 字节
            },
            "load": {
                "load1": round(psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') and psutil.getloadavg() else 0, 2),
                "load5": round(psutil.getloadavg()[1] if hasattr(psutil, 'getloadavg') and psutil.getloadavg() else 0, 2),
                "load15": round(psutil.getloadavg()[2] if hasattr(psutil, 'getloadavg') and psutil.getloadavg() else 0, 2)
            },
            "disk": {
                "total": disk_info["total"],          # 字节
                "used": disk_info["used"]             # 字节
            },
            "network": {
                "up": network_stats["up"],
                "down": network_stats["down"],
                "totalUp": network_stats["total_up"],
                "totalDown": network_stats["total_down"]
            },
            "connections": {
                "tcp": await self._get_tcp_connections(),
                "udp": await self._get_udp_connections()
            },
            "uptime": int(time.time() - psutil.boot_time()),
            "process": len(psutil.pids()),
            "message": ""
        }
        
        Logger.debug(f"实时监控数据: {json.dumps(info, indent=2)}", 2)
        return info
    
    def _get_cpu_name(self) -> str:
        """获取 CPU 名称"""
        try:
            if platform.system() == "Windows":
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
                cpu_name = winreg.QueryValueEx(key, "ProcessorNameString")[0]
                winreg.CloseKey(key)
                return cpu_name.strip()
            else:
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if line.strip().startswith('model name'):
                            return line.split(':')[1].strip()
        except Exception as e:
            Logger.debug(f"获取CPU名称失败: {e}", 1)
        
        return "Unknown CPU"
    
    async def _get_cpu_usage(self) -> float:
        """获取 CPU 使用率 (非阻塞，基于初始化的基准)"""
        async with self._cpu_init_lock:
            if not self._cpu_initialized:
                # 第一次调用时，执行一次阻塞的 cpu_percent 来设置基准
                # 这会在首次调用 get_realtime_info 时发生，只阻塞一次
                psutil.cpu_percent(interval=0.1) # 这里阻塞0.1秒设置初始值
                self._cpu_initialized = True
                # 返回0.0，因为这是第一次计算，没有可比较的前一个值
                return 0.0
        # 后续调用使用 interval=None，不阻塞，基于上一次的基准计算
        try:
            usage = psutil.cpu_percent(interval=None)
            return round(max(0, min(100, usage)), 2)
        except Exception as e:
            Logger.debug(f"获取CPU使用率失败: {e}", 2)
            return 0.0 # 出错时返回0
    
    async def _get_memory_info(self) -> Dict[str, int]:
        """获取内存信息（字节单位）"""
        try:
            virtual_memory = psutil.virtual_memory()
            swap_memory = psutil.swap_memory()
            
            return {
                "ram_total": virtual_memory.total,
                "ram_used": virtual_memory.used,
                "swap_total": swap_memory.total,
                "swap_used": swap_memory.used
            }
        except Exception as e:
            Logger.debug(f"获取内存信息失败: {e}", 2)
            return {
                "ram_total": 0,
                "ram_used": 0,
                "swap_total": 0,
                "swap_used": 0
            }
    
    def _get_physical_disk_device(self, device_path: str) -> Optional[str]:
        if platform.system() != "Linux":
            return device_path

        import os
        import re

        dev_name = device_path.replace("/dev/", "")
        if not dev_name:
            return None

        sd_match = re.match(r'^(sd[a-z]+)\d*$', dev_name)
        if sd_match:
            physical_name = sd_match.group(1)
            return f"/dev/{physical_name}"

        vd_match = re.match(r'^(vd[a-z]+)\d*$', dev_name)
        if vd_match:
            physical_name = vd_match.group(1)
            return f"/dev/{physical_name}"

        xvd_match = re.match(r'^(xvd[a-z]+)\d*$', dev_name)
        if xvd_match:
            physical_name = xvd_match.group(1)
            return f"/dev/{physical_name}"

        mmcblk_match = re.match(r'^(mmcblk\d+)p?\d*$', dev_name)
        if mmcblk_match:
            physical_name = mmcblk_match.group(1)
            return f"/dev/{physical_name}"

        nvme_match = re.match(r'^(nvme\d+n\d+)p?\d*$', dev_name)
        if nvme_match:
            physical_name = nvme_match.group(1)
            return f"/dev/{physical_name}"

        if not re.search(r'\d', dev_name):
             return device_path

        sys_block_path = f"/sys/block/{dev_name}"
        if os.path.exists(sys_block_path):
            real_parent = os.path.realpath(os.path.dirname(sys_block_path))
            real_path = os.path.realpath(sys_block_path)
            if not os.path.isdir(real_path):
                real_grandparent = os.path.dirname(real_parent)
                if real_grandparent.endswith('/sys/block'):
                    physical_name = os.path.basename(real_parent)
                    if self._is_physical_disk(f"/dev/{physical_name}"):
                        return f"/dev/{physical_name}"

        return None

    async def _get_disk_info(self) -> Dict[str, int]:
        try:
            total_bytes = 0
            used_bytes = 0
            seen_physical_devices = set()

            partitions = psutil.disk_partitions()
            Logger.debug(f"获取到 {len(partitions)} 个分区", 5)
            for partition in partitions:
                device = partition.device
                mountpoint = partition.mountpoint
                fstype = partition.fstype

                if fstype in {'tmpfs', 'devtmpfs', 'overlay', 'squashfs', 'proc', 'sysfs', 'debugfs', 'configfs', 'cgroup', 'cgroup2', 'pstore', 'bpf', 'tracefs', 'securityfs', 'efivarfs'}:
                    Logger.debug(f"跳过虚拟文件系统: {fstype} (设备: {device}, 挂载点: {mountpoint})", 5)
                    continue

                physical_device = self._get_physical_disk_device(device)
                if not physical_device:
                    Logger.debug(f"无法解析物理磁盘设备名，跳过分区: {device} (挂载点: {mountpoint})", 5)
                    continue

                if physical_device in seen_physical_devices:
                    Logger.debug(f"物理磁盘 {physical_device} 已处理，跳过分区: {device} (挂载点: {mountpoint})", 5)
                    continue

                if not self._is_physical_disk(physical_device):
                    Logger.debug(f"设备 {physical_device} (来自分区 {device}) 不是物理磁盘，跳过", 5)
                    continue

                try:
                    usage = psutil.disk_usage(mountpoint)
                    Logger.debug(
                        f"统计物理磁盘 {physical_device} (来自分区 {device}): 挂载点={mountpoint}, "
                        f"总空间={usage.total} 字节, 已用={usage.used} 字节, 可用={usage.free} 字节, 使用率={usage.percent:.2f}%",
                        5
                    )
                    total_bytes += usage.total
                    used_bytes += usage.used
                    Logger.debug(f"当前累计统计量: 总空间={total_bytes} 字节, 已用={used_bytes} 字节", 5)
                    seen_physical_devices.add(physical_device)
                except (PermissionError, OSError) as e:
                    Logger.debug(f"跳过分区 {device}（挂载点: {mountpoint}, 物理磁盘: {physical_device}）: {e}", 5)
                    continue

            Logger.debug(f"磁盘统计完成 (按物理磁盘去重): 总空间={total_bytes} 字节, 已用={used_bytes} 字节", 5)
            return {
                "total": total_bytes,
                "used": used_bytes
            }
        except Exception as e:
            Logger.debug(f"获取磁盘信息失败: {e}", 5)
            return {"total": 0, "used": 0}
    
    async def _get_disk_total(self) -> int:
        """获取磁盘总容量"""
        disk_info = await self._get_disk_info()
        return disk_info["total"]
    
    def _is_physical_disk(self, device: str) -> bool:
        if platform.system() == "Windows":
            return any(device.lower().startswith(drive) for drive in ['c:', 'd:', 'e:', 'f:', 'g:', 'h:'])
        else:
            import re
            physical_patterns = [
                r'^/dev/sd[a-z]+$',
                r'^/dev/vd[a-z]+$',
                r'^/dev/xvd[a-z]+$',
                r'^/dev/nvme[0-9]+n[0-9]+$',
                r'^/dev/mmcblk[0-9]+$',
            ]
            is_physical_device = any(re.match(pattern, device) for pattern in physical_patterns)
            return is_physical_device
    
    async def _get_network_stats(self) -> Dict[str, int]:
        """
        使用 psutil 按网卡获取网络统计（推荐）
        返回所有物理网卡的总和，排除虚拟网卡
        """
        try:
            # 获取所有网卡的IO统计
            net_io = psutil.net_io_counters(pernic=True)
            current_time = time.time()
            
            # 初始化累计变量
            total_current_rx = 0
            total_current_tx = 0
            
            # 定义要排除的虚拟网卡模式
            exclude_patterns = ['lo', 'docker', 'veth', 'br-', 'tun', 'virbr']
            
            # 遍历所有网卡，累加物理网卡的数据
            for interface, stats in net_io.items():
                # 检查是否为虚拟网卡
                if any(pattern in interface for pattern in exclude_patterns):
                    Logger.debug(f"排除虚拟网卡: {interface}", 4)
                    continue
                
                Logger.debug(f"统计物理网卡 {interface}: RX={stats.bytes_recv}, TX={stats.bytes_sent}", 4)
                total_current_rx += stats.bytes_recv
                total_current_tx += stats.bytes_sent
            
            # 后续计算逻辑与之前相同（瞬时速率和累计流量）
            # 第一次运行，初始化总流量为当前网卡累计值
            if self.last_network_stats['rx'] == 0:
                Logger.debug(f"第一次网络统计(psutil按网卡)，初始化总流量: 下载={total_current_rx}, 上传={total_current_tx}", 4)
                self.total_network_down = total_current_rx
                self.total_network_up = total_current_tx
                self.last_network_stats = {'rx': total_current_rx, 'tx': total_current_tx}
                self.last_network_time = current_time
                
                return {
                    "up": 0,
                    "down": 0,
                    "total_up": self.total_network_up,
                    "total_down": self.total_network_down
                }
            
            # 计算瞬时速率
            time_diff = current_time - self.last_network_time
            if time_diff > 0:
                down_speed = (total_current_rx - self.last_network_stats['rx']) / time_diff
                up_speed = (total_current_tx - self.last_network_stats['tx']) / time_diff
                
                # 确保速率不为负
                down_speed = max(0, down_speed)
                up_speed = max(0, up_speed)
                
                # 更新总流量：直接使用当前网卡累计值
                self.total_network_down = total_current_rx
                self.total_network_up = total_current_tx
                
                Logger.debug(f"网络统计(psutil按网卡): 下载速度={int(down_speed)} B/s, 上传速度={int(up_speed)} B/s, 总下载={self.total_network_down}, 总上传={self.total_network_up}", 4)
            
            # 更新统计值
            self.last_network_stats = {'rx': total_current_rx, 'tx': total_current_tx}
            self.last_network_time = current_time
            
            return {
                "up": int(up_speed),
                "down": int(down_speed),
                "total_up": self.total_network_up,
                "total_down": self.total_network_down
            }
            
        except Exception as e:
            Logger.debug(f"psutil 按网卡统计失败: {e}", 4)
            return {"up": 0, "down": 0, "total_up": 0, "total_down": 0}
    
    async def _get_tcp_connections(self) -> int:
        """获取 TCP 连接数"""
        try:
            if platform.system() == "Windows":
                # Windows 使用 netstat 命令
                result = subprocess.run(
                    ['netstat', '-n', '-p', 'tcp'], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                count = len([line for line in result.stdout.split('\n') if 'ESTABLISHED' in line])
                return count
            else:
                # Linux 使用 psutil
                connections = psutil.net_connections(kind='tcp')
                return len([conn for conn in connections if conn.status == 'ESTABLISHED'])
        except Exception as e:
            Logger.debug(f"获取TCP连接数失败: {e}", 2)
            return 0
    
    async def _get_udp_connections(self) -> int:
        """获取 UDP 连接数"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ['netstat', '-n', '-p', 'udp'], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                count = len([line for line in result.stdout.split('\n') if 'UDP' in line and line.strip()])
                return count
            else:
                connections = psutil.net_connections(kind='udp')
                return len(connections)
        except Exception as e:
            Logger.debug(f"获取UDP连接数失败: {e}", 2)
            return 0
    
    def _get_linux_distribution(self) -> Dict[str, str]:
        """获取 Linux 发行版信息"""
        try:
            if platform.system() == "Linux":
                if os.path.exists('/etc/os-release'):
                    with open('/etc/os-release', 'r') as f:
                        content = f.read()
                    
                    name = 'Unknown'
                    version = 'Unknown'
                    
                    for line in content.split('\n'):
                        if line.startswith('ID='):
                            name = line.replace('ID=', '').replace('"', '').strip()
                        elif line.startswith('VERSION_ID='):
                            version = line.replace('VERSION_ID=', '').replace('"', '').strip()
                    
                    return {'name': name, 'version': version}
        except Exception:
            pass
        
        return {'name': 'Unknown', 'version': 'Unknown'}
    
    def _get_virtualization(self) -> str:
        """获取虚拟化信息"""
        try:
            if platform.system() == "Linux":
                if os.path.exists('/.dockerenv'):
                    return 'Docker'
                
                if os.path.exists('/proc/1/cgroup'):
                    with open('/proc/1/cgroup', 'r') as f:
                        content = f.read()
                        if 'docker' in content:
                            return 'Docker'
                        elif 'lxc' in content:
                            return 'LXC'
                
                if os.path.exists('/proc/cpuinfo'):
                    with open('/proc/cpuinfo', 'r') as f:
                        content = f.read()
                        if 'QEMU' in content or 'KVM' in content:
                            return 'QEMU'
        except Exception:
            pass
        
        return 'None'
    
    async def _get_public_ip_v4(self) -> Optional[str]:
        """获取公网 IPv4 地址"""
        services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://checkip.amazonaws.com',
            'https://ifconfig.me/ip',
        ]
        
        for service in services:
            try:
                ip = await self._fetch_ip(service)
                if ip and self._is_valid_ipv4(ip):
                    return ip
            except Exception:
                continue
        
        return None
    
    async def _get_public_ip_v6(self) -> Optional[str]:
        """获取公网 IPv6 地址"""
        services = [
            'https://api6.ipify.org',
            'https://icanhazip.com',
        ]
        
        for service in services:
            try:
                ip = await self._fetch_ip(service)
                if ip and self._is_valid_ipv6(ip):
                    return ip
            except Exception:
                continue
        
        return None
    
    async def _fetch_ip(self, url: str) -> str:
        """获取 IP 地址"""
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers={'User-Agent': self.VERSION}) as response:
                if response.status == 200:
                    return (await response.text()).strip()
                else:
                    raise Exception(f"HTTP {response.status}")
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """验证 IPv4 地址"""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            return False
    
    def _is_valid_ipv6(self, ip: str) -> bool:
        """验证 IPv6 地址"""
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

class TerminalSessionHandler:
    """终端会话处理器"""
    
    def __init__(self):
        self.heartbeat_timeout = None
        self.last_heartbeat = 0
        self.HEARTBEAT_TIMEOUT = 30  # 30秒
    
    async def start_session(self, request_id: str, server: str, token: str):
        """启动终端会话"""
        log = lambda msg: Logger.info(f"[终端会话 {request_id}] {msg}")
        
        log("启动终端会话")
        
        try:
            terminal_url = server.replace('http', 'ws') + f"/api/clients/terminal?token={token}&id={request_id}"
            log(f"连接终端 WebSocket: {terminal_url}")
            
            async with websockets.connect(terminal_url) as websocket:
                log("终端 WebSocket 连接成功")
                await self._run_terminal(websocket, request_id, log)
                
        except Exception as e:
            log(f"终端会话异常: {e}")
        
        log("终端会话结束")
    
    async def _run_terminal(self, websocket, request_id: str, log):
        """运行终端"""
        try:
            # 创建主从 PTY
            master, slave = pty.openpty()
            
            # 启动 shell 进程
            shell = os.environ.get('SHELL', '/bin/bash')
            if platform.system() == "Windows":
                shell = "cmd.exe"
            
            process = await asyncio.create_subprocess_shell(
                shell,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            log(f"启动终端进程: {shell}")
            
            # 创建任务处理双向数据流
            tasks = [
                self._handle_pty_output(websocket, master, log),
                self._handle_websocket_input(websocket, master, log),
                self._monitor_process(websocket, process, log)
            ]
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            log(f"终端运行异常: {e}")
    
    async def _handle_pty_output(self, websocket, master, log):
        """处理 PTY 输出到 WebSocket"""
        try:
            while True:
                # 使用 select 检查是否有数据可读
                rlist, _, _ = select.select([master], [], [], 0.1)
                if master in rlist:
                    try:
                        data = os.read(master, 1024)
                        if data:
                            await websocket.send(data)
                    except (OSError, BlockingIOError):
                        break
                await asyncio.sleep(0.01)
        except Exception as e:
            log(f"处理PTY输出异常: {e}")
    
    async def _handle_websocket_input(self, websocket, master, log):
        """处理 WebSocket 输入到 PTY"""
        try:
            async for message in websocket:
                if isinstance(message, bytes):
                    # 二进制数据直接写入 PTY
                    os.write(master, message)
                elif isinstance(message, str):
                    try:
                        data = json.loads(message)
                        if data.get('type') == 'input' and 'data' in data:
                            # Base64 解码输入数据
                            import base64
                            input_data = base64.b64decode(data['data']).decode()
                            os.write(master, input_data.encode())
                            log(f"收到终端输入，长度: {len(input_data)} 字符")
                    except json.JSONDecodeError:
                        # 普通文本数据
                        os.write(master, message.encode())
        except Exception as e:
            log(f"处理WebSocket输入异常: {e}")
    
    async def _monitor_process(self, websocket, process, log):
        """监控进程状态"""
        try:
            await process.wait()
            log(f"终端进程退出，代码: {process.returncode}")
        except Exception as e:
            log(f"监控进程异常: {e}")

class EventHandler:
    """事件处理器"""
    
    def __init__(self, config: Dict[str, Any], disable_remote_control: bool = False):
        self.config = config
        self.disable_remote_control = disable_remote_control
        self.session = aiohttp.ClientSession()
    
    async def handle_event(self, event: Dict[str, Any]):
        """处理事件"""
        message_type = event.get('message', '')
        
        Logger.info(f"收到服务器事件: {message_type}")
        Logger.debug(f"事件详情: {json.dumps(event, indent=2)}", 2)
        
        if message_type == 'exec':
            await self._handle_remote_exec(event)
        elif message_type == 'ping':
            await self._handle_ping_task(event)
        elif message_type == 'terminal':
            await self._handle_terminal(event)
        else:
            Logger.warning(f"未知的事件类型: {message_type}")
    
    async def _handle_remote_exec(self, event: Dict[str, Any]):
        """处理远程执行"""
        if self.disable_remote_control:
            Logger.warning("远程执行功能已被禁用，忽略任务")
            return
        
        task_id = event.get('task_id', '')
        command = event.get('command', '')
        
        if not task_id or not command:
            Logger.error("远程执行任务缺少必要参数: task_id 或 command")
            return
        
        # 额外的命令安全检查（可选）
        if self._is_dangerous_command(command):
            Logger.warning(f"检测到可能危险的命令，拒绝执行: {command}")
            await self._report_exec_result(task_id, "命令被拒绝执行：安全检查未通过", -3)
            return
        
        Logger.info(f"执行远程命令: {command}")
        await self._execute_command(task_id, command)

    def _is_dangerous_command(self, command: str) -> bool:
        """检查是否为危险命令（基础安全检查）"""
        dangerous_patterns = [
            'rm -rf /', 'dd if=',':(){ :|:& };:','reboot','poweroff',  
        ]
        command_lower = command.lower()
        return any(pattern in command_lower for pattern in dangerous_patterns)
    
    async def _execute_command(self, task_id: str, command: str):
        """执行命令"""
        try:
            start_time = time.time()
            
            # 根据平台选择合适的shell
            if platform.system() == "Windows":
                # Windows 使用 PowerShell
                shell_cmd = ["powershell", "-Command", command]
                shell_exec = False
            else:
                # Linux/Unix 使用 sh
                shell_cmd = ["sh", "-c", command]
                shell_exec = False
            
            Logger.info(f"执行命令: {' '.join(shell_cmd)}")
            
            # 使用 asyncio 创建子进程，设置超时
            process = await asyncio.create_subprocess_exec(
                *shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
            
            try:
                # 等待进程完成，设置30秒超时
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=30.0
                )
                
                execution_time = time.time() - start_time
                
                # 解码输出
                output = ""
                if stdout:
                    output += stdout.decode('utf-8', errors='replace')
                if stderr:
                    if output:  # 如果已经有stdout输出，添加分隔符
                        output += "\n=== STDERR ===\n"
                    output += stderr.decode('utf-8', errors='replace')
                
                exit_code = process.returncode
                
                Logger.info(f"命令执行完成，耗时: {execution_time:.2f}s, 退出码: {exit_code}")
                
                # 限制输出长度，避免过大
                if len(output) > 10000:
                    output = output[:10000] + f"\n... (输出被截断，总长度: {len(output)} 字符)"
                if not output:
                    output+=f"无输出结果"
                await self._report_exec_result(task_id, output, exit_code)
                
            except asyncio.TimeoutError:
                # 命令执行超时
                Logger.warning(f"命令执行超时，强制终止进程")
                try:
                    process.terminate()
                    await asyncio.sleep(1)
                    if process.returncode is None:
                        process.kill()
                except:
                    pass
                
                error_msg = "命令执行超时（30秒）"
                await self._report_exec_result(task_id, error_msg, -2)
                
        except asyncio.TimeoutError:
            # 这里应该不会执行到，因为上面的communicate已经处理了超时
            error_msg = "命令执行超时"
            await self._report_exec_result(task_id, error_msg, -2)
        except Exception as e:
            Logger.error(f"命令执行异常: {e}")
            await self._report_exec_result(task_id, f"命令执行异常: {e}", -1)
    
    async def _report_exec_result(self, task_id: str, result: str, exit_code: int):
        """上报执行结果"""
        report_url = f"{self.config['http_server']}/api/clients/task/result?token={self.config['token']}"
        
        # 确保时间格式正确（RFC3339 或带时区的 ISO 格式）
        from datetime import timezone
        finished_at = datetime.now(timezone.utc).isoformat()
        
        report_data = {
            "task_id": task_id,
            "result": result,
            "exit_code": exit_code,
            "finished_at": finished_at
        }
        
        Logger.debug(f"上报执行结果: {json.dumps(report_data, indent=2)}", 2)
        
        try:
            async with self.session.post(report_url, json=report_data) as response:
                if response.status in (200, 201):
                    Logger.info("执行结果上报成功")
                else:
                    error_body = await response.text()
                    Logger.error(f"执行结果上报失败 - HTTP: {response.status}, 响应: {error_body}")
        except Exception as e:
            Logger.error(f"执行结果上报异常: {e}")
    
    async def _handle_ping_task(self, event: Dict[str, Any]):
        """处理网络探测任务"""
        task_id = event.get('ping_task_id', '')
        ping_type = event.get('ping_type', '')
        target = event.get('ping_target', '')
        
        if not task_id or not ping_type or not target:
            Logger.error("网络探测任务缺少必要参数")
            return
        
        Logger.info(f"执行网络探测: {ping_type} -> {target}")
        await self._execute_ping(task_id, ping_type, target)
    
    async def _execute_ping(self, task_id: str, ping_type: str, target: str):
        """执行网络探测"""
        try:
            latency = -1
            
            if ping_type == 'icmp':
                latency = await self._ping_icmp(target)
            elif ping_type == 'tcp':
                latency = await self._ping_tcp(target)
            elif ping_type == 'http':
                latency = await self._ping_http(target)
            else:
                Logger.error(f"不支持的探测类型: {ping_type}")
                return
            
            await self._report_ping_result(task_id, ping_type, latency)
            
        except Exception as e:
            Logger.error(f"网络探测异常: {e}")
            await self._report_ping_result(task_id, ping_type, -1)
    
    async def _ping_icmp(self, target: str) -> float:
        """ICMP Ping"""
        try:
            if platform.system() == "Windows":
                command = f"ping -n 1 {target}"
            else:
                command = f"ping -c 1 -W 1 {target}"
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            # 解析 ping 结果
            if platform.system() == "Windows":
                if "时间" in output:
                    import re
                    match = re.search(r'时间[=<](\d+)ms', output)
                    if match:
                        return float(match.group(1))
            else:
                if "time=" in output:
                    import re
                    match = re.search(r'time=([\d.]+)\s*ms', output)
                    if match:
                        return float(match.group(1))
            
            return -1
            
        except Exception:
            return -1
    
    async def _ping_tcp(self, target: str) -> float:
        """TCP Ping"""
        try:
            host, port = target.split(':') if ':' in target else (target, '80')
            port = int(port)
            
            start_time = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3.0
            )
            latency = (time.time() - start_time) * 1000  # 转换为毫秒
            writer.close()
            await writer.wait_closed()
            return latency
            
        except Exception:
            return -1
    
    async def _ping_http(self, target: str) -> float:
        """HTTP Ping"""
        try:
            url = target if target.startswith('http') else f"http://{target}"
            
            start_time = time.time()
            async with self.session.get(url, timeout=5.0) as response:
                latency = (time.time() - start_time) * 1000
                return latency
                
        except Exception:
            return -1
    
    async def _report_ping_result(self, task_id: str, ping_type: str, value: float):
        """上报网络探测结果"""
        result_data = {
            "type": "ping_result",
            "task_id": int(task_id),
            "ping_type": ping_type,
            "value": value,
            "finished_at": datetime.now().isoformat()
        }
        
        Logger.debug(f"上报网络探测结果: {json.dumps(result_data, indent=2)}", 2)
        # 注意：这里需要通过 WebSocket 上报，在主监控循环中实现
    
    async def _handle_terminal(self, event: Dict[str, Any]):
        """处理终端连接"""
        if self.disable_remote_control:
            Logger.warning("远程终端功能已被禁用，忽略请求")
            return
        
        request_id = event.get('request_id', '')
        if not request_id:
            Logger.error("终端连接请求缺少 request_id")
            return
        
        Logger.info(f"建立终端连接: {request_id}")
        await self._start_terminal_session(request_id)
    
    async def _start_terminal_session(self, request_id: str):
        """启动终端会话"""
        log = lambda msg: Logger.info(f"[终端会话] {msg}")
        
        log(f"启动终端会话: {request_id}")
        
        try:
            handler = TerminalSessionHandler()
            await handler.start_session(
                request_id,
                self.config['http_server'],
                self.config['token']
            )
        except Exception as e:
            log(f"启动终端会话失败: {e}")
    
    async def close(self):
        """关闭资源"""
        await self.session.close()

class KomariMonitorClient:
    """主监控客户端"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.disable_remote_control = config.get('disable_remote_control', False)
        self.system_info = SystemInfoCollector()
        self.event_handler = EventHandler(config, self.disable_remote_control)
        self.last_basic_info_report = 0
        self.BASIC_INFO_INTERVAL = 300  # 5分钟
    
    async def run(self):
        """运行监控客户端"""
        Logger.info("启动 Komari 监控客户端 (Python 版本)")
        if self.disable_remote_control:
            Logger.info("远程控制功能已禁用")
        
        while True:
            try:
                await self._run_monitoring_cycle()
                await asyncio.sleep(self.config.get('reconnect_interval', 5))
            except Exception as e:
                Logger.error(f"监控周期出错: {e}")
                Logger.info(f"{self.config.get('reconnect_interval', 5)}秒后重试...")
                await asyncio.sleep(self.config.get('reconnect_interval', 5))
    
    async def _run_monitoring_cycle(self):
        """运行监控周期"""
        basic_info_url = f"{self.config['http_server']}/api/clients/uploadBasicInfo?token={self.config['token']}"
        ws_url = self.config['http_server'].replace('http', 'ws') + f"/api/clients/report?token={self.config['token']}"
        
        # 启动时立即上报基础信息
        await self._push_basic_info(basic_info_url)
        
        # 启动 WebSocket 监控
        await self._start_websocket_monitoring(ws_url, basic_info_url)
    
    async def _push_basic_info(self, url: str) -> bool:
        """推送基础信息"""
        basic_info = await self.system_info.get_basic_info()
        
        # 在推送前打印基础信息数据，按照指定格式
        Logger.info("基础信息上报数据:")
        Logger.info(json.dumps(basic_info, indent=2))
        print(json.dumps(basic_info, indent=1))
        Logger.debug(f"推送基础信息到: {url}", 1)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=basic_info) as response:
                    if response.status in (200, 201):
                        Logger.info("基础信息推送成功")
                        self.last_basic_info_report = time.time()
                        return True
                    else:
                        Logger.error(f"基础信息推送失败 - HTTP: {response.status}")
                        return False
        except Exception as e:
            Logger.error(f"基础信息推送异常: {e}")
            return False
    
    async def _start_websocket_monitoring(self, ws_url: str, basic_info_url: str):
        """启动 WebSocket 监控"""
        Logger.debug(f"启动 WebSocket 监控: {ws_url}", 2)
        
        try:
            async with websockets.connect(ws_url) as websocket:
                Logger.info("WebSocket 连接成功，开始监控")
                
                # 启动消息处理任务
                message_task = asyncio.create_task(self._handle_websocket_messages(websocket))
                monitoring_task = asyncio.create_task(self._monitoring_loop(websocket, basic_info_url))
                
                # 等待任意任务完成
                done, pending = await asyncio.wait(
                    [message_task, monitoring_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # 取消未完成的任务
                for task in pending:
                    task.cancel()
                
        except Exception as e:
            Logger.error(f"WebSocket 监控异常: {e}")
        finally:
            Logger.info("WebSocket 连接关闭")
    
    async def _handle_websocket_messages(self, websocket):
        """处理 WebSocket 消息"""
        try:
            async for message in websocket:
                try:
                    if isinstance(message, str):
                        event = json.loads(message)
                        Logger.debug(f"收到服务器消息: {json.dumps(event, indent=2)}", 2)
                        await self.event_handler.handle_event(event)
                    else:
                        Logger.debug(f"收到二进制消息，长度: {len(message)}", 2)
                except Exception as e:
                    Logger.error(f"处理WebSocket消息异常: {e}")
        except Exception as e:
            Logger.error(f"WebSocket消息循环异常: {e}")
    
    async def _monitoring_loop(self, websocket, basic_info_url: str):
        """监控循环"""
        sequence = 0
        interval = max(0.1, self.config.get('interval', 1.0))
        
        while True:
            start_time = time.time()
            
            # 检查是否需要上报基础信息（5分钟一次）
            current_time = time.time()
            if current_time - self.last_basic_info_report >= self.BASIC_INFO_INTERVAL:
                success = await self._push_basic_info(basic_info_url)
                if success:
                    self.last_basic_info_report = current_time
                else:
                    # 如果推送失败，等待一段时间再重试，避免频繁重试
                    self.last_basic_info_report = current_time - self.BASIC_INFO_INTERVAL + 30  # 30秒后重试
            
            # 获取并发送实时监控数据
            realtime_info = await self.system_info.get_realtime_info()
            
            Logger.debug(f"准备发送实时数据: {json.dumps(realtime_info, indent=2)}", 2)
            
            try:
                await websocket.send(json.dumps(realtime_info))
                sequence += 1
                Logger.debug(f"第 {sequence} 条数据发送成功", 2)
            except Exception as e:
                Logger.error(f"发送监控数据失败: {e}")
                break
            
            # 控制发送频率
            elapsed = time.time() - start_time
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

def parse_args() -> Dict[str, Any]:
    """解析命令行参数"""
    args = {
        'http_server': '',
        'token': '',
        'interval': 1.0,
        'reconnect_interval': 5,
        'ignore_unsafe_cert': True,
        'log_level': 0,
        'disable_remote_control': False
    }
    
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == '--http-server' and i + 1 < len(argv):
            args['http_server'] = argv[i + 1]
            i += 1
        elif arg == '--token' and i + 1 < len(argv):
            args['token'] = argv[i + 1]
            i += 1
        elif arg == '--interval' and i + 1 < len(argv):
            args['interval'] = float(argv[i + 1])
            i += 1
        elif arg == '--log-level' and i + 1 < len(argv):
            args['log_level'] = int(argv[i + 1])
            i += 1
        elif arg == '--disable-web-ssh':
            args['disable_remote_control'] = True
        elif arg in ('--help', '-h'):
            _show_help()
            sys.exit(0)
        i += 1
    
    return args

def parse_env_args() -> Dict[str, Any]:
    """解析环境变量"""
    return {
        'http_server': os.getenv('KOMARI_HTTP_SERVER', ''),
        'token': os.getenv('KOMARI_TOKEN', ''),
        'interval': float(os.getenv('KOMARI_INTERVAL', '5.0')),
        'reconnect_interval': int(os.getenv('KOMARI_RECONNECT_INTERVAL', '10')),
        'ignore_unsafe_cert': os.getenv('KOMARI_IGNORE_UNSAFE_CERT', 'true').lower() != 'false',
        'log_level': int(os.getenv('KOMARI_LOG_LEVEL', '0')),
        'disable_remote_control': os.getenv('KOMARI_DISABLE_REMOTE_CONTROL', 'false').lower() == 'true'
    }

def merge_config(cli_config: dict, env_config: dict) -> dict:
    # 只保留非空命令行参数
    filtered_cli = {
        k: v for k, v in cli_config.items()
        if v not in [None, '', []]
    }
    # 环境变量作为基础，命令行参数覆盖非空项
    return {**env_config, **filtered_cli}

def get_final_config() -> Dict[str, Any]:
    """获取最终配置"""
    cli_config = parse_args()
    need_env = not cli_config['http_server'] or not cli_config['token']
    env_config = parse_env_args() if need_env else {}
    
    config = merge_config(cli_config, env_config)
    print(cli_config)
    if not config['http_server']:
        print("错误: 必须提供 --http-server 参数或设置 KOMARI_HTTP_SERVER 环境变量")
        _show_help()
        sys.exit(1)
    
    if not config['token']:
        print("错误: 必须提供 --token 参数或设置 KOMARI_TOKEN 环境变量")
        _show_help()
        sys.exit(1)
    
    return config

def _show_help():
    """显示帮助信息"""
    print("komari-agent-python 1.0.0")
    print()
    print("用法: python komari_agent.py --token <token> [选项]")
    print()
    print("选项:")
    print("  --http-server <url>        服务器地址 (也可通过 KOMARI_HTTP_SERVER 环境变量设置) (必须)")
    print("  --token <token>            认证令牌 (也可通过 KOMARI_TOKEN 环境变量设置) (必须)")
    print("  --interval <sec>           实时数据上报间隔 (默认: 1.0秒，可通过 KOMARI_INTERVAL 环境变量设置)")
    print("  --log-level <level>        日志级别: 0=关闭Debug日志, 1=基本信息, 2=WebSocket传输，3=终端日志，4网络统计日志，5磁盘统计日志")
    print("  --disable-web-ssh          禁用远程控制功能 (远程执行和终端)")
    print("  --help                     显示此帮助信息")
    print()
    print("环境变量配置:")
    print("  所有命令行参数均可通过环境变量设置，环境变量优先级低于命令行参数。")

async def check_environment() -> bool:
    """检查运行环境"""
    print("正在检查运行环境...")
    
    errors = []
    warnings = []
    
    # 检查 Python 版本
    python_version = sys.version_info
    if python_version < (3, 7):
        errors.append("需要 Python 3.7 或更高版本")
    else:
        print(f"✅ Python 版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # 检查必要模块
    required_modules = [
        ('aiohttp', 'aiohttp'),
        ('websockets', 'websockets'), 
        ('psutil', 'psutil')
    ]
    
    for module_name, package_name in required_modules:
        try:
            __import__(package_name)
            print(f"✅ 模块 {module_name} 可用")
        except ImportError:
            errors.append(f"缺少必要模块: {module_name}，请运行: pip install {package_name}")
    
    # 检查系统命令
    if platform.system() != "Windows":
        required_commands = ['ping']
        for cmd in required_commands:
            try:
                subprocess.run(['which', cmd], capture_output=True, check=True)
                print(f"✅ 系统命令 {cmd} 可用")
            except subprocess.CalledProcessError:
                warnings.append(f"缺少系统命令: {cmd}，部分功能可能受限")
    
    # 检查 PTY 支持
    if platform.system() != "Windows":
        try:
            import pty
            print("✅ PTY 终端支持可用")
        except ImportError:
            warnings.append("PTY 支持不可用，终端功能将受限")
    
    if warnings:
        print("\n⚠️  警告:")
        for warning in warnings:
            print(f"   - {warning}")
    
    if errors:
        print("\n❌ 环境检查失败，发现以下问题:")
        for error in errors:
            print(f"   - {error}")
        return False
    
    print("✅ 环境检查通过，所有依赖项均可用")
    return True

async def main():
    """主函数"""
    try:
        config = get_final_config()
        
        # 环境检查并启动监控
        if await check_environment():
            Logger.set_log_level(config['log_level'])
            client = KomariMonitorClient(config)
            await client.run()
        else:
            sys.exit(1)
            
    except KeyboardInterrupt:
        Logger.info("程序被用户中断")
    except Exception as e:
        Logger.error(f"程序异常: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
