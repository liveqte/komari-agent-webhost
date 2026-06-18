#!/usr/bin/env node

/**
 * komari-agent-node by liming2038
 */

const WebSocket = require('ws');
const { spawn, exec, execSync } = require('child_process');
const os = require('os');
const fs = require('fs');
const https = require('https');
const http = require('http');
const net = require('net');
const { log } = require('console');

function parseEnvArgs() {
    return {
        http_server: process.env.KOMARI_HTTP_SERVER || '',
        token: process.env.KOMARI_TOKEN || '',
        interval: parseFloat(process.env.KOMARI_INTERVAL || '1.0'),
        reconnect_interval: parseInt(process.env.KOMARI_RECONNECT_INTERVAL || '5'),
        ignore_unsafe_cert: process.env.KOMARI_IGNORE_UNSAFE_CERT !== 'false',
        log_level: parseInt(process.env.KOMARI_LOG_LEVEL || '0'),
        disable_remote_control: process.env.KOMARI_DISABLE_REMOTE_CONTROL === 'true',
        terminal_request_id: process.env.KOMARI_TERMINAL_REQUEST_ID || ''
    };
}

const commandAvailability = {
    script: false,
    ping: false, 
    df: false,
    python: false,
    python3: false
};

// 日志类
class Logger {
    static logLevel = 0; // 0=关闭, 1=基本信息, 2=WebSocket传输,，3=终端日志，4网络统计日志，5磁盘统计日志,6=环境检查日志

    static setLogLevel(level) {
        this.logLevel = level;
    }

    static log(message, level = 'INFO') {
        const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
        const logMessage = `[${timestamp}] [${level}] ${message}`;
        console.log(logMessage);
        
        if (level === 'ERROR') {
            process.stderr.write(logMessage + '\n');
        }
    }

    static debug(message, debugLevel = 1) {
        if (this.logLevel === debugLevel) {
            this.log(message, 'DEBUG');
        }
    }

    static error(message,errorlevel) {
        if (this.logLevel === errorlevel) {
            this.log(message, 'ERROR');
        }
    }

    static info(message,infolevel=1) {
        if (this.logLevel === infolevel) {
            this.log(message, 'INFO');
        }
    }

    static warning(message,warningLevel = 1) {
        if (this.logLevel === warningLevel) {
            this.log(message, 'WARNING');
        }
    }
}

// 系统信息收集器
class SystemInfoCollector {
    static version = 'komari-agent-node-1.0.0';
    static lastNetworkStats = { rx: 0, tx: 0 };
    static totalNetworkUp = 0;
    static totalNetworkDown = 0;
    static lastNetworkTime = Date.now();
    static lastCpuMeasure = null;

    static async getBasicInfo() {
        const dist = this.getLinuxDistribution();
        let ipv4 = null;
        let ipv6 = null;
        try {
            [ipv4, ipv6] = await Promise.all([
                this.getPublicIpV4(),
                this.getPublicIpV6()
            ]);
        } catch (error) {
            Logger.debug(`获取 IP 地址失败: ${error.message}`, 1);
        }
        
        const distOs = (dist.name !== 'Unknown' && dist.version !== 'Unknown') 
            ? `${dist.name} ${dist.version}` 
            : os.type();

        const info = {
            arch: os.arch(),
            cpu_cores: os.cpus().length,
            cpu_name: os.cpus()[0]?.model || 'Unknown CPU',
            disk_total: this.getDiskTotal(),
            gpu_name: '', // Node.js 暂不支持 GPU 检测
            ipv4: ipv4,
            ipv6: ipv6,
            mem_total: os.totalmem(), // 保持字节单位
            os: distOs,
            kernel_version: os.release(),
            swap_total: this.getSwapTotal(),
            version: this.version,
            virtualization: this.getVirtualization()
        };

        Logger.debug(`基础信息数据: ${JSON.stringify(info, null, 2)}`, 1);
        return info;
    }

    static getRealtimeInfo() {
        // 计算 CPU 使用率
        const cpuUsage = this.getCpuUsage();
        
        // 获取网络统计
        const networkStats = this.getNetworkStats();
        
        // 获取负载平均值
        const loadavg = os.loadavg();
        
        // 获取准确的内存和磁盘信息（字节单位）
        const memoryInfo = this.getMemoryInfo();
        const diskInfo = this.getDiskInfo();
    
        const info = {
            cpu: {
                usage: cpuUsage
            },
            ram: {
                total: memoryInfo.ramTotal,    // 字节
                used: memoryInfo.ramUsed       // 字节
            },
            swap: {
                total: memoryInfo.swapTotal,   // 字节
                used: memoryInfo.swapUsed      // 字节
            },
            load: {
                load1: Math.round(loadavg[0] * 100) / 100,
                load5: Math.round(loadavg[1] * 100) / 100,
                load15: Math.round(loadavg[2] * 100) / 100
            },
            disk: {
                total: diskInfo.total,         // 字节
                used: diskInfo.used            // 字节
            },
            network: {
                up: networkStats.up,
                down: networkStats.down,
                totalUp: networkStats.total_up,
                totalDown: networkStats.total_down
            },
            connections: {
                tcp: this.getTcpConnections(),
                udp: this.getUdpConnections()
            },
            uptime: Math.round(os.uptime()),
            process: this.getProcessCount(),
            message: ""
        };
    
        Logger.debug(`实时监控数据: ${JSON.stringify(info, null, 2)}`, 2);
        return info;
    }
    static getMemoryInfo() {
        try {
            if (process.platform === 'win32') {
                // Windows 系统 - 使用 wmic 获取准确内存信息
                return this.getWindowsMemoryInfo();
            } else {
                // Linux/Unix 系统 - 从 /proc/meminfo 获取准确信息
                return this.getLinuxMemoryInfo();
            }
        } catch (error) {
            Logger.debug(`获取内存信息失败: ${error.message}`, 2);
            // 回退到 Node.js 原生方法
            return {
                ramTotal: Math.round(os.totalmem() / 1024 / 1024), // 转换为 MB
                ramUsed: Math.round((os.totalmem() - os.freemem()) / 1024 / 1024),
                swapTotal: 0,
                swapUsed: 0
            };
        }
    }
    static getLinuxMemoryInfo() {
        try {
            const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
            
            // 解析内存信息（保持KB单位，在调用处转换为字节）
            const memTotal = this.parseMemInfo(meminfo, 'MemTotal');
            const memAvailable = this.parseMemInfo(meminfo, 'MemAvailable') || 
                               this.parseMemInfo(meminfo, 'MemFree');
            const swapTotal = this.parseMemInfo(meminfo, 'SwapTotal');
            const swapFree = this.parseMemInfo(meminfo, 'SwapFree');
            
            // KB 转字节
            const ramTotal = memTotal * 1024;
            const ramUsed = (memTotal - memAvailable) * 1024;
            const swapTotalBytes = swapTotal * 1024;
            const swapUsedBytes = (swapTotal - swapFree) * 1024;
    
            return {
                ramTotal,
                ramUsed,
                swapTotal: swapTotalBytes,
                swapUsed: swapUsedBytes
            };
        } catch (error) {
            throw new Error(`解析Linux内存信息失败: ${error.message}`);
        }
    }
    static getWindowsMemoryInfo() {
        try {
            const memoryOutput = execSync('wmic ComputerSystem get TotalPhysicalMemory /value', { encoding: 'utf8' });
            const totalMemoryMatch = memoryOutput.match(/TotalPhysicalMemory=(\d+)/);
            
            const memoryUsedOutput = execSync('wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value', { encoding: 'utf8' });
            const totalMatch = memoryUsedOutput.match(/TotalVisibleMemorySize=(\d+)/);
            const freeMatch = memoryUsedOutput.match(/FreePhysicalMemory=(\d+)/);
            
            let ramTotal = 0;
            let ramUsed = 0;
            
            if (totalMemoryMatch) {
                ramTotal = parseInt(totalMemoryMatch[1]); // 已经是字节单位
            }
            
            if (totalMatch && freeMatch) {
                const totalKB = parseInt(totalMatch[1]);
                const freeKB = parseInt(freeMatch[1]);
                ramUsed = (totalKB - freeKB) * 1024; // KB 转字节
            }
    
            return {
                ramTotal,
                ramUsed,
                swapTotal: 0,
                swapUsed: 0
            };
        } catch (error) {
            throw new Error(`解析Windows内存信息失败: ${error.message}`);
        }
    }
    static parseMemInfo(meminfo, key) {
        const regex = new RegExp(`${key}:\\s+(\\d+)\\s+kB`);
        const match = meminfo.match(regex);
        return match ? parseInt(match[1]) : 0;
    }
    // 修复磁盘信息获取
    static getDiskInfo() {
        try {
            if (process.platform === 'win32') {
                return this.getWindowsDiskInfo();
            } else {
                return this.getLinuxDiskInfo();
            }
        } catch (error) {
            Logger.debug(`获取磁盘信息失败: ${error.message}`, 2);
            return {
                total: 0,
                used: 0
            };
        }
    }
    
    static getLinuxDiskInfo() {
        try {
            // 获取所有文件系统信息
            const dfOutput = execSync('df -B1', { encoding: 'utf8' });
            const lines = dfOutput.trim().split('\n');
            
            let totalBytes = 0;
            let usedBytes = 0;
            const processedDevices = new Set();
            
            // 跳过标题行
            for (let i = 1; i < lines.length; i++) {
                const parts = lines[i].trim().split(/\s+/);
                if (parts.length >= 6) {
                    const device = parts[0];
                    
                    // 只处理物理磁盘
                    if (this.isPhysicalDisk(device) && !processedDevices.has(device)) {
                        processedDevices.add(device);
                        const deviceTotal = parseInt(parts[1]);
                        const deviceUsed = parseInt(parts[2]);
                        
                        totalBytes += deviceTotal;
                        usedBytes += deviceUsed;
                        
                        Logger.debug(`物理磁盘: ${device}, 大小=${deviceTotal}字节, 已用=${deviceUsed}字节`, 2);
                    }
                }
            }
            
            Logger.debug(`所有物理磁盘总计: 总大小=${totalBytes}字节, 已用=${usedBytes}字节`, 2);
            
            return {
                total: totalBytes,
                used: usedBytes
            };
            
        } catch (error) {
            Logger.debug(`获取物理磁盘信息失败: ${error.message}`, 2);
        }
        
        return {
            total: 0,
            used: 0
        };
    }
    
    static isPhysicalDisk(device) {
        // 物理磁盘设备通常以 /dev/ 开头，且不是虚拟设备
        const physicalPatterns = [
            /^\/dev\/sd[a-z]+/,      // SATA/SCSI 磁盘
            /^\/dev\/vd[a-z]+/,      // VirtIO 磁盘
            /^\/dev\/xvd[a-z]+/,     // Xen 磁盘
            /^\/dev\/nvme[0-9]+n[0-9]+/, // NVMe 磁盘
            /^\/dev\/mmcblk[0-9]+/,  // MMC/SD 卡
            /^\/dev\/disk\/by-id\//, // 磁盘 ID 链接
            /^\/dev\/md[0-9]+/,      // Linux 软件 RAID (mdX)
            /^\/dev\/mapper\//,                    // LVM 逻辑卷（关键！包括你的 ubuntu--vg-ubuntu--lv）
            /^\/dev\/dm-[0-9]+/,                   // 设备映射器底层设备（LVM、加密卷等）
            /^\/dev\/disk\/by-id\//,               // 磁盘 ID 链接
            /^\/dev\/disk\/by-uuid\//,             // UUID 链接
            /^\/dev\/disk\/by-partuuid\//,         // PARTUUID 链接
            /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._\/-]+$/,         // ZFS 数据集 (zroot/...)
        ];
        
        const virtualPatterns = [
            /^tmpfs$/,
            /^devtmpfs$/,
            /^overlay$/,
            /^squashfs$/,
            /^proc$/,
            /^sysfs$/,
            /^cgroup$/,
            /^udev$/,
            /^devpts$/,
            /^mqueue$/,
            /^hugetlbfs$/,
            /^securityfs$/,
            /^pstore$/,
            /^efivarfs$/,
            /^autofs$/,
            /^debugfs$/,
            /^tracefs$/,
            /^fusectl$/,
            /^fuse\./,
            /^rpc_pipefs$/,
        ];
        
        // 检查是否为物理磁盘
        const isPhysical = physicalPatterns.some(pattern => pattern.test(device));
        
        // 检查是否为虚拟文件系统
        const isVirtual = virtualPatterns.some(pattern => pattern.test(device));
        
        return isPhysical && !isVirtual;
    }
    static getWindowsDiskInfo() {
        try {
            // 获取所有逻辑磁盘
            const diskOutput = execSync('wmic logicaldisk get Size,FreeSpace,DeviceID /value', { encoding: 'utf8' });
            const disks = diskOutput.trim().split('\n\n');
            
            let totalBytes = 0;
            let usedBytes = 0;
            
            for (const disk of disks) {
                if (disk.trim()) {
                    const sizeMatch = disk.match(/Size=(\d+)/);
                    const freeMatch = disk.match(/FreeSpace=(\d+)/);
                    const deviceMatch = disk.match(/DeviceID=([A-Z]:)/);
                    
                    if (sizeMatch && freeMatch && deviceMatch) {
                        const deviceTotal = parseInt(sizeMatch[1]);
                        const deviceFree = parseInt(freeMatch[1]);
                        const deviceUsed = deviceTotal - deviceFree;
                        
                        totalBytes += deviceTotal;
                        usedBytes += deviceUsed;
                        
                        Logger.debug(`Windows磁盘: ${deviceMatch[1]}, 大小=${deviceTotal}字节, 已用=${deviceUsed}字节`, 2);
                    }
                }
            }
            
            Logger.debug(`Windows所有磁盘总计: 总大小=${totalBytes}字节, 已用=${usedBytes}字节`, 2);
            
            return {
                total: totalBytes,
                used: usedBytes
            };
            
        } catch (error) {
            Logger.debug(`获取Windows磁盘信息失败: ${error.message}`, 2);
        }
        
        return {
            total: 0,
            used: 0
        };
    }
    
    static getDiskTotal() {
        const diskInfo = this.getDiskInfo();
        return diskInfo.total; // 转回字节
    }
    
    static getDiskUsed() {
        const diskInfo = this.getDiskInfo();
        return diskInfo.used; // 转回字节
    }
    static getSwapTotal() {
        const memoryInfo = this.getMemoryInfo();
        return memoryInfo.swapTotal; // 转回字节
    }

    static getSwapUsed() {
        const memoryInfo = this.getMemoryInfo();
        return memoryInfo.swapUsed; // 转回字节
    }

    static getCpuUsage() {
        const cpus = os.cpus();
        let totalIdle = 0;
        let totalTick = 0;

        cpus.forEach(cpu => {
            for (let type in cpu.times) {
                totalTick += cpu.times[type];
            }
            totalIdle += cpu.times.idle;
        });

        const currentMeasure = { totalIdle, totalTick, timestamp: Date.now() };

        if (!this.lastCpuMeasure) {
            this.lastCpuMeasure = currentMeasure;
            return 0;
        }

        const idleDifference = currentMeasure.totalIdle - this.lastCpuMeasure.totalIdle;
        const totalDifference = currentMeasure.totalTick - this.lastCpuMeasure.totalTick;
        const timeDifference = currentMeasure.timestamp - this.lastCpuMeasure.timestamp;

        let percentageCpu = 0;
        if (totalDifference > 0 && timeDifference > 0) {
            percentageCpu = 100 - (100 * idleDifference / totalDifference);
        }

        this.lastCpuMeasure = currentMeasure;
        return Math.round(Math.max(0, Math.min(100, percentageCpu)) * 100) / 100;
    }

    static getProcessCount() {
        try {
            if (process.platform === 'win32') {
                const result = execSync('tasklist /fo csv | find /c /v ""', { encoding: 'utf8' });
                return parseInt(result.trim()) - 3; // 减去标题行和空行
            } else {
                // 使用 /proc 目录统计进程数
                if (!fs.existsSync('/proc')) {
                    return 0;
                }
                
                let count = 0;
                try {
                    const files = fs.readdirSync('/proc');
                    for (const file of files) {
                        // 只统计数字目录（进程目录）
                        if (/^\d+$/.test(file)) {
                            // 进一步验证：检查 status 文件是否存在
                            if (fs.existsSync(`/proc/${file}/status`)) {
                                count++;
                            }
                        }
                    }
                } catch (error) {
                    Logger.debug(`读取 /proc 目录失败: ${error.message}`, 2);
                    return 0;
                }
                
                return count;
            }
        } catch (error) {
            Logger.debug(`获取进程数失败: ${error.message}`, 2);
            return 0;
        }
    }

    static getTcpConnections() {
        try {
            if (process.platform === 'win32') {
                const result = execSync('netstat -n | find "TCP" | find /c "ESTABLISHED"', { encoding: 'utf8' });
                return parseInt(result.trim()) || 0;
            } else {
                // 使用 /proc/net/tcp 文件获取 TCP 连接数
                if (!fs.existsSync('/proc/net/tcp')) {
                    return 0;
                }
                
                const tcpContent = fs.readFileSync('/proc/net/tcp', 'utf8');
                const tcpLines = tcpContent.trim().split('\n');
                let count = 0;
                
                // 跳过标题行，统计所有 TCP 连接
                for (let i = 1; i < tcpLines.length; i++) {
                    const line = tcpLines[i].trim();
                    if (line) {
                        count++;
                    }
                }
                
                return count;
            }
        } catch (error) {
            Logger.debug(`获取TCP连接数失败: ${error.message}`, 2);
            return 0;
        }
    }

    static getUdpConnections() {
        try {
            if (process.platform === 'win32') {
                const result = execSync('netstat -n | find "UDP" | find /c /v ""', { encoding: 'utf8' });
                return parseInt(result.trim()) || 0;
            } else {
                // 使用 /proc/net/udp 文件获取 UDP 连接数
                if (!fs.existsSync('/proc/net/udp')) {
                    return 0;
                }
                
                const udpContent = fs.readFileSync('/proc/net/udp', 'utf8');
                const udpLines = udpContent.trim().split('\n');
                let count = 0;
                
                // 跳过标题行，统计所有 UDP 连接
                for (let i = 1; i < udpLines.length; i++) {
                    const line = udpLines[i].trim();
                    if (line) {
                        count++;
                    }
                }
                
                return count;
            }
        } catch (error) {
            Logger.debug(`获取UDP连接数失败: ${error.message}`, 2);
            return 0;
        }
    }

    
    static getNetworkStats() {
        try {
            if (process.platform === 'win32') {
                return {
                    up: 0,
                    down: 0,
                    total_up: 0,
                    total_down: 0
                };
            }

            const netDev = fs.readFileSync('/proc/net/dev', 'utf8');
            let rx = 0, tx = 0;

            netDev.split('\n').forEach(line => {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('Inter-') && !trimmed.startsWith('face')) {
                    const parts = trimmed.split(/\s+/);
                    if (parts.length >= 10) {
                        const interfaceName = parts[0].replace(':', '');
                        if (interfaceName !== 'lo' && 
                            !interfaceName.startsWith('docker') &&
                            !interfaceName.startsWith('veth') &&
                            !interfaceName.startsWith('br-') &&
                            !interfaceName.startsWith('tun')) {
                            
                            rx += parseInt(parts[1]);  // 接收字节 = 下载
                            tx += parseInt(parts[9]);  // 发送字节 = 上传
                        }
                    }
                }
            });

            const currentTime = Date.now();
            let up = 0, down = 0;

            // 如果是第一次运行，初始化总流量为当前网卡累计值
            if (this.lastNetworkStats.rx === 0 && this.lastNetworkStats.tx === 0) {
                Logger.debug(`第一次网络统计，初始化总流量: 下载=${rx}, 上传=${tx}`, 4);
                this.totalNetworkDown = rx; // 总下载流量从当前网卡累计值开始
                this.totalNetworkUp = tx;   // 总上传流量从当前网卡累计值开始
                this.lastNetworkStats = { rx, tx };
                this.lastNetworkTime = currentTime;
                
                return {
                    up: 0,
                    down: 0,
                    total_up: this.totalNetworkUp,
                    total_down: this.totalNetworkDown
                };
            }

            const timeDiff = (currentTime - this.lastNetworkTime) / 1000;
            
            if (timeDiff > 0) {
                // 计算瞬时速率
                down = Math.round((rx - this.lastNetworkStats.rx) / timeDiff); // 下载速度
                up = Math.round((tx - this.lastNetworkStats.tx) / timeDiff);   // 上传速度
                
                // 确保速率不为负
                down = Math.max(0, down);
                up = Math.max(0, up);
                
                // 更新总流量：直接使用当前网卡累计值
                this.totalNetworkDown = rx; // 总下载流量 = 当前网卡累计下载
                this.totalNetworkUp = tx;   // 总上传流量 = 当前网卡累计上传
                
                Logger.debug(`网络统计: 下载速度=${down} B/s, 上传速度=${up} B/s, 总下载=${this.totalNetworkDown}, 总上传=${this.totalNetworkUp}`, 4);
            }

            // 更新上一次的统计值和时间
            this.lastNetworkStats = { rx, tx };
            this.lastNetworkTime = currentTime;
            Logger.debug(`下载总流量=${this.totalNetworkDown} B/s, 上传总流量=${this.totalNetworkUp} B/s`, 4);
            return {
                up: up,           // 上传速度
                down: down,       // 下载速度
                total_up: this.totalNetworkUp,     // 总上传流量
                total_down: this.totalNetworkDown  // 总下载流量
            };
        } catch (error) {
            Logger.debug(`获取网络统计失败: ${error.message}`, 2);
            return { up: 0, down: 0, total_up: 0, total_down: 0 };
        }
    }
    static getLinuxDistribution() {
        try {
            if (fs.existsSync('/etc/os-release')) {
                const content = fs.readFileSync('/etc/os-release', 'utf8');
                let name = 'Unknown', version = 'Unknown';
                
                content.split('\n').forEach(line => {
                    if (line.startsWith('ID=')) {
                        name = line.replace('ID=', '').replace(/"/g, '').trim();
                    } else if (line.startsWith('VERSION_ID=')) {
                        version = line.replace('VERSION_ID=', '').replace(/"/g, '').trim();
                    }
                });
                return { name, version };
            }
        } catch (error) {
            // 忽略错误
        }
        return { name: 'Unknown', version: 'Unknown' };
    }

    static getVirtualization() {
        try {
            if (fs.existsSync('/.dockerenv')) {
                return 'Docker';
            }

            if (fs.existsSync('/proc/1/environ')) {
                const environ = fs.readFileSync('/proc/1/environ', 'utf8');
                if (environ.includes('container=lxc')) {
                    return 'LXC';
                }
            }

            if (fs.existsSync('/proc/cpuinfo')) {
                const cpuinfo = fs.readFileSync('/proc/cpuinfo', 'utf8');
                if (cpuinfo.includes('QEMU') || cpuinfo.includes('KVM')) {
                    return 'QEMU';
                }
            }
        } catch (error) {
            // 忽略错误
        }
        return 'None';
    }
    static getLocalIPv4() {
        const nets = os.networkInterfaces();
        for (const name of Object.keys(nets)) {
            for (const net of nets[name]) {
                if (net.family === 'IPv4' && !net.internal) {
                    // 过滤掉典型的内网地址段
                    if (!/^10\./.test(net.address) &&
                        !/^192\.168\./.test(net.address) &&
                        !/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(net.address)) {
                        return net.address;
                    }
                }
            }
        }
        return null;
    }
    static async getPublicIpV4() {
        // 优先尝试本地接口
        const localIp = this.getLocalIPv4();
        if (localIp && this.isValidIPv4(localIp)) {
            return localIp;
        }

        // 回退到外部服务
        const services = [
            'https://api.ipify.org',
            'https://icanhazip.com',
            'https://checkip.amazonaws.com',
            'https://ifconfig.me/ip',
            'https://ipecho.net/plain',
            'https://ipinfo.io/ip',
            'https://myexternalip.com/raw'
        ];

        for (const service of services) {
            try {
                const ip = await this.fetchIP(service);
                if (ip && this.isValidIPv4(ip)) {
                    return ip;
                }
            } catch (error) {
                continue;
            }
        }
        return null;
    }
    static getLocalIPv6() {
        const nets = os.networkInterfaces();
        for (const name of Object.keys(nets)) {
            for (const net of nets[name]) {
                if (net.family === 'IPv6' && !net.internal) {
                    // 过滤掉链路本地地址 (fe80::/10)
                    if (!net.address.startsWith('fe80:')) {
                        return net.address;
                    }
                }
            }
        }
        return null;
    }
    static async getPublicIpV6() {
        // 优先尝试本地接口
        const localIp = this.getLocalIPv6();

        Logger.debug(`localip is${localIp}`, 1);

        if (localIp && this.isValidIPv6(localIp)) {
            return localIp;
        }

        // 回退到外部服务
        const services = [
            'https://api6.ipify.org',
            'https://icanhazip.com',
            'https://v6.ident.me'
        ];

        for (const service of services) {
            try {
                const ip = await this.fetchIP(service);
                if (ip && this.isValidIPv6(ip)) {
                    return ip;
                }
            } catch (error) {
                continue;
            }
        }
        return null;
    }

    static fetchIP(url) {
        return new Promise((resolve, reject) => {
            const https = require('https');
            const options = {
                timeout: 5000,
                headers: {
                    'User-Agent': 'komari-agent-node',
                    'Accept': 'text/plain'
                }
            };

            const req = https.get(url, options, (res) => {
                let data = '';
                
                // 检查状态码
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}`));
                    return;
                }
                
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => resolve(data.trim()));
            });
            
            req.on('error', reject);
            req.setTimeout(5000, () => {
                req.destroy();
                reject(new Error('请求超时'));
            });
        });
    }
    
    static isValidIPv4(ip) {
        return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
    }

    static isValidIPv6(ip) {
        return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
    }
}

// WebSocket 客户端类
class KomariWebSocketClient {
    constructor(url) {
        this.url = url;
        this.ws = null;
        this.connected = false;
        this.reconnectTimer = null;
        this.messageCallbacks = [];
    }

    async connect() {
        return new Promise((resolve, reject) => {
            Logger.debug(`尝试连接 WebSocket: ${this.url}`, 2);

            try {
                this.ws = new WebSocket(this.url, {
                    perMessageDeflate: false,
                    handshakeTimeout: 10000,
                    headers: {
                        'User-Agent': SystemInfoCollector.version
                    }
                });

                this.ws.on('open', () => {
                    Logger.debug('WebSocket 连接成功', 2);
                    this.connected = true;
                    resolve(true);
                });

                this.ws.on('error', (error) => {
                    Logger.error(`WebSocket 连接错误: ${error.message}`);
                    this.connected = false;
                    reject(error);
                });

                this.ws.on('close', (code, reason) => {
                    Logger.debug(`WebSocket 连接关闭: ${code} - ${reason}`, 2);
                    this.connected = false;
                });

                this.ws.on('message', (data) => {
                    this.messageCallbacks.forEach(callback => {
                        try {
                            callback(data);
                        } catch (error) {
                            Logger.error(`消息回调处理错误: ${error.message}`);
                        }
                    });
                });

            } catch (error) {
                Logger.error(`WebSocket 连接异常: ${error.message}`);
                reject(error);
            }
        });
    }

    send(data) {
        if (!this.isConnected()) {
            Logger.error('WebSocket 未连接，无法发送数据');
            return false;
        }

        try {
            const jsonData = JSON.stringify(data);
            Logger.debug(`发送 WebSocket 数据: ${jsonData}`, 2);
            this.ws.send(jsonData);
            return true;
        } catch (error) {
            Logger.error(`发送数据异常: ${error.message}`);
            return false;
        }
    }

    sendBinary(data) {
        if (!this.isConnected()) {
            return false;
        }

        try {
            this.ws.send(data);
            return true;
        } catch (error) {
            Logger.error(`发送二进制数据异常: ${error.message}`);
            return false;
        }
    }

    close() {
        if (this.ws) {
            this.ws.close();
            this.connected = false;
        }
    }

    isConnected() {
        return this.connected && this.ws && this.ws.readyState === WebSocket.OPEN;
    }

    onMessage(callback) {
        this.messageCallbacks.push(callback);
    }

    removeMessageCallback(callback) {
        const index = this.messageCallbacks.indexOf(callback);
        if (index > -1) {
            this.messageCallbacks.splice(index, 1);
        }
    }
}

// 简化版终端会话处理器 (使用普通子进程)
class TerminalSessionHandler {
    constructor() {
        this.heartbeatTimeout = null;
        this.lastHeartbeat = 0;
        this.HEARTBEAT_TIMEOUT = 30000; // 30秒
    }
    // 心跳管理方法
    setupHeartbeatMonitor(wsClient, log, onTimeout) {
        this.lastHeartbeat = Date.now();
        
        // 清除现有定时器
        if (this.heartbeatTimeout) {
            clearTimeout(this.heartbeatTimeout);
        }
        
        // 设置新的心跳检查
        this.heartbeatTimeout = setTimeout(() => {
            const timeSinceLastHeartbeat = Date.now() - this.lastHeartbeat;
            if (timeSinceLastHeartbeat > this.HEARTBEAT_TIMEOUT) {
                log(`心跳超时，${this.HEARTBEAT_TIMEOUT/1000}秒未收到服务端心跳`);
                onTimeout();
            } else {
                // 继续监控
                this.setupHeartbeatMonitor(wsClient, log, onTimeout);
            }
        }, 1000); // 每秒检查一次
    }

    updateHeartbeat() {
        this.lastHeartbeat = Date.now();
    }

    cleanupHeartbeatMonitor() {
        if (this.heartbeatTimeout) {
            clearTimeout(this.heartbeatTimeout);
            this.heartbeatTimeout = null;
        }
    }
    // 消息处理包装器
    createMessageHandler(terminalProcess, log) {
        return (data) => {
            try {
                const message = JSON.parse(data.toString());
                
                if (message.type === 'heartbeat') {
                    // 更新心跳时间
                    this.updateHeartbeat();
                    log('收到服务端心跳包');
                    return; // 心跳包不转发给终端进程
                }
                
                // 其他消息正常处理
                this.handleTerminalInput(message, terminalProcess, log);
            } catch (error) {
                // 如果不是JSON，可能是二进制数据，直接转发给终端
                if (Buffer.isBuffer(data)) {
                    terminalProcess.stdin.write(data);
                }
            }
        };
    }
    async startSession(requestId, server, token) {
        const log = (message) => {
            Logger.info(`[终端会话 ${requestId}] ${message}`,3);
        };

        log('启动终端会话');

        try {
            const terminalUrl = server.replace(/^http/, 'ws') + 
                `/api/clients/terminal?token=${token}&id=${requestId}`;
            
            log(`连接终端 WebSocket: ${terminalUrl}`);

            const wsClient = new KomariWebSocketClient(terminalUrl);
            
            if (await wsClient.connect()) {
                log('终端 WebSocket 连接成功');
                await this.runTerminal(wsClient, requestId, log);
            } else {
                log('终端 WebSocket 连接失败');
            }
        } catch (error) {
            log(`终端会话异常: ${error.message}`);
        }

        log('终端会话结束');
    }
    static resolveShell() {
        if (process.platform === 'win32') {
          return 'cmd.exe';
        }
      
        try {
          // 尝试获取 SHELL 环境变量对应的实际路径
          const shellEnv = process.env.SHELL || '/bin/sh';
          const resolved = execSync(`command -v ${shellEnv}`, { encoding: 'utf8' }).trim();
          return resolved || '/bin/sh';
        } catch (err) {
          // 如果解析失败，回退到默认 shell
          return '/bin/sh';
        }
    }
    async runTerminal(wsClient, requestId, log) {
        try {
            const shell = this.constructor.resolveShell();
            let terminalProcess;
            
            if (process.platform !== 'win32') {
                // 方法1: 如果 script 命令可用，尝试使用 script 创建伪终端
                if (commandAvailability.script) {
                    try {
                        terminalProcess = spawn('script', ['-q', '-c', shell, '/dev/null'], {
                            stdio: ['pipe', 'pipe', 'pipe'],
                            env: { ...process.env, TERM: 'xterm-256color' }
                        });
                        log('使用 script 命令创建 PTY 终端');
                    } catch (error) {
                        log(`script 命令执行失败: ${error.message}, 尝试 Python pty`);
                        commandAvailability.script = false; // 标记为不可用，下次不再尝试
                        // 继续尝试其他方法
                    }
                }
                // 方法2: 如果 script 不可用但 python3 可用，尝试使用 Python pty.spawn
                if (!commandAvailability.script && commandAvailability.python3) {
                    try {
                        terminalProcess = spawn('python3', ['-c', `import pty; pty.spawn("${shell}")`], {
                            stdio: ['pipe', 'pipe', 'pipe'],
                            env: { ...process.env, TERM: 'xterm-256color' }
                        });
                        log('使用 Python pty.spawn 创建 PTY 终端');
                    } catch (pythonError) {
                        log(`Python pty 执行失败: ${pythonError.message}`);
                        commandAvailability.python3 = false; // 标记为不可用，下次不再尝试
                        // 继续尝试其他方法
                    }
                }

                // 方法3: 如果 python3 不可用但 python 可用，尝试使用 Python pty.spawn
                if (!commandAvailability.script && !commandAvailability.python3 && commandAvailability.python) {
                    try {
                        terminalProcess = spawn('python', ['-c', `import pty; pty.spawn("${shell}")`], {
                            stdio: ['pipe', 'pipe', 'pipe'],
                            env: { ...process.env, TERM: 'xterm-256color' }
                        });
                        log('使用 Python pty.spawn 创建 PTY 终端');
                    } catch (pythonError) {
                        log(`Python pty 执行失败: ${pythonError.message}`);
                        commandAvailability.python = false; // 标记为不可用，下次不再尝试
                        // 继续尝试其他方法
                    }
                }
            } else {
                // Windows 系统使用普通 cmd
                terminalProcess = spawn(shell, [], {
                    stdio: ['pipe', 'pipe', 'pipe'],
                    env: process.env
                });
                log(`启动 Windows 终端: ${shell}`);
            }
    
            // 设置心跳监控
            this.setupHeartbeatMonitor(wsClient, log, () => {
                log('心跳超时，关闭终端会话');
                if (!terminalProcess.killed) {
                    terminalProcess.kill();
                }
                wsClient.close();
            });

            // 设置消息处理 - 使用包装器
            const messageHandler = this.createMessageHandler(terminalProcess, log);
            wsClient.onMessage(messageHandler);

            // 处理终端输出
            terminalProcess.stdout.on('data', (data) => {
                if (wsClient.isConnected()) {
                    wsClient.sendBinary(data);
                }
            });

            terminalProcess.stderr.on('data', (data) => {
                if (wsClient.isConnected()) {
                    wsClient.sendBinary(data);
                }
            });

            // 处理进程退出
            terminalProcess.on('exit', (code) => {
                log(`终端进程退出，代码: ${code}`);
                this.cleanupHeartbeatMonitor();
                wsClient.close();
            });

            terminalProcess.on('error', (error) => {
                log(`终端进程错误: ${error.message}`);
                this.cleanupHeartbeatMonitor();
                wsClient.close();
            });

            // 等待连接关闭或进程退出
            await new Promise((resolve) => {
                const checkInterval = setInterval(() => {
                    if (!wsClient.isConnected() || terminalProcess.killed) {
                        clearInterval(checkInterval);
                        this.cleanupHeartbeatMonitor();
                        if (!terminalProcess.killed) {
                            terminalProcess.kill();
                        }
                        resolve();
                    }
                }, 1000);
            });

        } catch (error) {
            log(`终端运行异常: ${error.message}`);
            this.cleanupHeartbeatMonitor();
        }
    }

    handleTerminalInput(data, terminalProcess, log) {
        try {
            // 严格检查数据类型
            if (Buffer.isBuffer(data)) {
                // 二进制数据直接转发给终端
                terminalProcess.stdin.write(data);
                return;
            }
            
            // 尝试解析 JSON 消息
            if (typeof data === 'string') {
                try {
                    const message = JSON.parse(data);
                    
                    // 验证消息结构
                    if (!message || typeof message !== 'object') {
                        log(`无效消息格式: ${data}`);
                        return;
                    }
                    
                    // 处理不同类型的消息
                    switch (message.type) {
                        case 'input':
                            if (message.data && typeof message.data === 'string') {
                                const input = Buffer.from(message.data, 'base64').toString();
                                terminalProcess.stdin.write(input);
                                log(`收到终端输入，长度: ${input.length} 字符`);
                            }
                            break;
                            
                        case 'resize':
                            if (typeof message.cols === 'number' && typeof message.rows === 'number') {
                                log(`调整终端大小: ${message.cols}x${message.rows}`);
                                // 这里可以处理终端大小调整逻辑
                            }
                            break;
                            
                        case 'heartbeat':
                            // 心跳包已经在外部处理，这里忽略
                            break;
                            
                        default:
                            log(`未知消息类型: ${message.type}`);
                            break;
                    }
                } catch (parseError) {
                    // 如果不是 JSON，可能是普通文本，直接转发
                    terminalProcess.stdin.write(data);
                }
            }
        } catch (error) {
            log(`处理终端输入异常: ${error.message}`);
        }
    }
}

// 事件处理器
class EventHandler {
    constructor(config, disableRemoteControl = false) {
        this.config = config;
        this.disableRemoteControl = disableRemoteControl;
    }

    handleEvent(event) {
        const messageType = event.message || '';
        
        Logger.info(`收到服务器事件: ${messageType}`,2);
        Logger.debug(`事件详情: ${JSON.stringify(event, null, 2)}`, 2);
        
        switch (messageType) {
            case 'exec':
                this.handleRemoteExec(event);
                break;
                
            case 'ping':
                this.handlePingTask(event);
                break;
                
            case 'terminal':
                this.handleTerminal(event);
                break;
                
            default:
                Logger.warning(`未知的事件类型: ${messageType}`);
                break;
        }
    }

    handleRemoteExec(event) {
        if (this.disableRemoteControl) {
            Logger.warning('远程执行功能已被禁用，忽略任务');
            return;
        }

        const taskId = event.task_id || '';
        const command = event.command || '';

        if (!taskId || !command) {
            Logger.error('远程执行任务缺少必要参数: task_id 或 command');
            return;
        }

        Logger.info(`执行远程命令: ${command}`,3);
        this.executeCommand(taskId, command);
    }

    async executeCommand(taskId, command) {
        try {
            const startTime = Date.now();
            
            exec(command, { timeout: 30000 }, (error, stdout, stderr) => {
                const executionTime = (Date.now() - startTime) / 1000;
                
                let output, exitCode;
                if (error) {
                    output = stderr || error.message;
                    exitCode = error.code || -1;
                } else {
                    output = stdout;
                    exitCode = 0;
                }

                Logger.info(`命令执行完成，耗时: ${executionTime}s`,3);
                this.reportExecResult(taskId, output, exitCode);
            });

        } catch (error) {
            Logger.error(`命令执行异常: ${error.message}`);
            this.reportExecResult(taskId, `命令执行异常: ${error.message}`, -1);
        }
    }

    async reportExecResult(taskId, result, exitCode) {
        const reportUrl = `${this.config.http_server}/api/clients/task/result?token=${this.config.token}`;
        
        const reportData = {
            task_id: taskId,
            result: result,
            exit_code: exitCode,
            finished_at: new Date().toISOString()
        };

        Logger.debug(`上报执行结果: ${JSON.stringify(reportData, null, 2)}`, 2);

        try {
            const response = await this.httpRequest(reportUrl, 'POST', reportData);
            if (response.statusCode >= 200 && response.statusCode < 300) {
                Logger.info('执行结果上报成功',3);
            } else {
                Logger.error(`执行结果上报失败 - HTTP: ${response.statusCode}`,3);
            }
        } catch (error) {
            Logger.error(`执行结果上报异常: ${error.message}`);
        }
    }

    handlePingTask(event) {
        const taskId = event.ping_task_id || '';
        const pingType = event.ping_type || '';
        const target = event.ping_target || '';

        if (!taskId || !pingType || !target) {
            Logger.error('网络探测任务缺少必要参数');
            return;
        }

        Logger.info(`执行网络探测: ${pingType} -> ${target}`,3);
        this.executePing(taskId, pingType, target);
    }

    async executePing(taskId, pingType, target) {
        try {
            let latency = -1;

            switch (pingType) {
                case 'icmp':
                    latency = await this.pingICMP(target);
                    break;
                    
                case 'tcp':
                    latency = await this.pingTCP(target);
                    break;
                    
                case 'http':
                    latency = await this.pingHTTP(target);
                    break;
                    
                default:
                    Logger.error(`不支持的探测类型: ${pingType}`);
                    return;
            }

            this.reportPingResult(taskId, pingType, latency);
        } catch (error) {
            Logger.error(`网络探测异常: ${error.message}`);
            this.reportPingResult(taskId, pingType, -1);
        }
    }

    async pingICMP(target) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            const command = process.platform === 'win32' 
                ? `ping -n 1 ${target}`
                : `ping -c 1 -W 1 ${target}`;
                
            exec(command, (error, stdout) => {
                if (error) {
                    resolve(-1);
                    return;
                }
                
                const match = stdout.match(/time=([\d.]+)\s*ms/);
                resolve(match ? parseFloat(match[1]) : -1);
            });
        });
    }

    async pingTCP(target) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            const [host, port = 80] = target.split(':');
            
            const socket = new net.Socket();
            socket.setTimeout(3000);
            
            socket.connect(parseInt(port), host, () => {
                const latency = Date.now() - startTime;
                socket.destroy();
                resolve(latency);
            });
            
            socket.on('error', () => resolve(-1));
            socket.on('timeout', () => resolve(-1));
        });
    }

    async pingHTTP(target) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            const url = target.startsWith('http') ? target : `http://${target}`;
            
            const protocol = url.startsWith('https') ? https : http;
            
            const req = protocol.get(url, { 
                timeout: 5000,
                headers: {
                    'User-Agent': SystemInfoCollector.version
                }
            }, (res) => {
                const latency = Date.now() - startTime;
                resolve(latency);
                req.destroy();
            });
            
            req.on('error', () => resolve(-1));
            req.on('timeout', () => resolve(-1));
        });
    }

    reportPingResult(taskId, pingType, value) {
        const resultData = {
            type: 'ping_result',
            task_id: parseInt(taskId),
            ping_type: pingType,
            value: value,
            finished_at: new Date().toISOString()
        };

        Logger.debug(`上报网络探测结果: ${JSON.stringify(resultData, null, 2)}`, 2);
        // 这里需要通过 WebSocket 上报，在 MonitorClient 中实现
    }

    handleTerminal(event) {
        if (this.disableRemoteControl) {
            Logger.warning('远程终端功能已被禁用，忽略请求');
            return;
        }

        const requestId = event.request_id || '';
        if (!requestId) {
            Logger.error('终端连接请求缺少 request_id');
            return;
        }

        Logger.info(`建立终端连接: ${requestId}`,3);
        this.startTerminalSession(requestId);
    }

    async startTerminalSession(requestId) {
        const log = (message) => {
            Logger.info(`[终端会话] ${message}`,3);
        };

        log(`启动终端会话: ${requestId}`);

        if (this.disableRemoteControl) {
            log('远程控制已禁用，忽略终端请求');
            return;
        }

        try {
            const handler = new TerminalSessionHandler();
            await handler.startSession(
                requestId, 
                this.config.http_server, 
                this.config.token
            );
        } catch (error) {
            log(`启动终端会话失败: ${error.message}`);
        }
    }

    httpRequest(url, method = 'GET', data = null) {
        return new Promise((resolve, reject) => {
            const parsedUrl = new URL(url);
            const options = {
                hostname: parsedUrl.hostname,
                port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
                path: parsedUrl.pathname + parsedUrl.search,
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': SystemInfoCollector.version
                },
                rejectUnauthorized: !this.config.ignore_unsafe_cert
            };

            const protocol = parsedUrl.protocol === 'https:' ? https : http;
            const req = protocol.request(options, (res) => {
                let responseData = '';
                res.on('data', (chunk) => responseData += chunk);
                res.on('end', () => resolve({
                    statusCode: res.statusCode,
                    data: responseData
                }));
            });

            req.on('error', reject);
            
            if (data) {
                req.write(JSON.stringify(data));
            }
            
            req.end();
        });
    }
}

// 主监控客户端
class KomariMonitorClient {
    constructor(config) {
        this.config = config;
        this.disableRemoteControl = config.disable_remote_control || false;
        this.eventHandler = new EventHandler(config, this.disableRemoteControl);
        this.lastBasicInfoReport = 0;
        this.BASIC_INFO_INTERVAL = 300; // 5分钟
    }

    async run() {
        Logger.info('启动 Komari 监控客户端 (Node.js 版本)',1);
        if (this.disableRemoteControl) {
            Logger.info('远程控制功能已禁用',1);
        }

        while (true) {
            try {
                await this.runMonitoringCycle();
                await this.delay(this.config.reconnect_interval * 1000);
            } catch (error) {
                Logger.error(`监控周期出错: ${error.message}`,1);
                Logger.info(`${this.config.reconnect_interval}秒后重试...`,1);
                await this.delay(this.config.reconnect_interval * 1000);
            }
        }
    }

    async runMonitoringCycle() {
        const basicInfoUrl = `${this.config.http_server}/api/clients/uploadBasicInfo?token=${this.config.token}`;
        const wsUrl = this.config.http_server.replace(/^http/, 'ws') + 
            `/api/clients/report?token=${this.config.token}`;

        // 启动时立即上报基础信息
        await this.pushBasicInfo(basicInfoUrl);

        // 启动 WebSocket 监控
        await this.startWebSocketMonitoring(wsUrl, basicInfoUrl);
    }

    async pushBasicInfo(url) {
        const basicInfo = await SystemInfoCollector.getBasicInfo();

        Logger.debug(`推送基础信息到: ${url}`, 1);

        try {
            const response = await this.eventHandler.httpRequest(url, 'POST', basicInfo);
            if (response.statusCode >= 200 && response.statusCode < 300) {
                Logger.info('基础信息推送成功',1);
                this.lastBasicInfoReport = Date.now(); // 成功时更新
                return true;
            } else {
                Logger.error(`基础信息推送失败 - HTTP: ${response.statusCode}`,1);
                // 失败时不更新 lastBasicInfoReport，下次循环会继续尝试
                return false;
            }
        } catch (error) {
            Logger.error(`基础信息推送异常: ${error.message}`,1);
            return false;
        }
    }

    async startWebSocketMonitoring(wsUrl, basicInfoUrl) {
        Logger.debug(`启动 WebSocket 监控: ${wsUrl}`, 2);

        const wsClient = new KomariWebSocketClient(wsUrl);

        try {
            await wsClient.connect();
            Logger.info('WebSocket 连接成功，开始监控');

            let sequence = 0;
            const interval = Math.max(100, this.config.interval * 1000);

            // 设置消息处理器
            wsClient.onMessage((data) => {
                try {
                    const message = JSON.parse(data.toString());
                    Logger.debug(`收到服务器消息: ${JSON.stringify(message, null, 2)}`, 2);
                    this.eventHandler.handleEvent(message);
                } catch (error) {
                    Logger.debug(`收到二进制消息，长度: ${data.length}`, 2);
                }
            });

            // 监控循环
            while (wsClient.isConnected()) {
                const startTime = Date.now();

                // 检查是否需要上报基础信息 - 修复：只在需要时上报
                const currentTime = Date.now();
                if (currentTime - this.lastBasicInfoReport >= this.BASIC_INFO_INTERVAL * 1000) {
                    await this.pushBasicInfo(basicInfoUrl);
                    this.lastBasicInfoReport = currentTime; // 重要：更新最后上报时间
                }

                // 获取并发送实时监控数据
                const realtimeInfo = SystemInfoCollector.getRealtimeInfo();
                
                Logger.debug(`准备发送实时数据: ${JSON.stringify(realtimeInfo, null, 2)}`, 2);
                
                if (!wsClient.send(realtimeInfo)) {
                    Logger.error('发送监控数据失败');
                    break;
                }

                Logger.debug(`第 ${++sequence} 条数据发送成功`, 2);

                const elapsed = Date.now() - startTime;
                const sleepTime = Math.max(0, interval - elapsed);
                
                if (sleepTime > 0) {
                    await this.delay(sleepTime);
                }
            }

        } catch (error) {
            Logger.error(`WebSocket 监控异常: ${error.message}`,2);
        } finally {
            wsClient.close();
            Logger.info('WebSocket 连接关闭',2);
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// 配置解析
function parseArgs() {
    const args = {
        http_server: '',
        token: '',
        interval: 1.0,
        reconnect_interval: 5,
        ignore_unsafe_cert: true,
        log_level: 0,
        disable_remote_control: false,
        terminal_request_id: ''
    };

    const argv = process.argv.slice(2);
    
    for (let i = 0; i < argv.length; i++) {
        switch (argv[i]) {
            case '--http-server':
                args.http_server = argv[++i];
                break;
            case '--token':
                args.token = argv[++i];
                break;
            case '--interval':
                args.interval = parseFloat(argv[++i]);
                break;
            case '--log-level':
                args.log_level = parseInt(argv[++i]);
                break;
            case '--disable-web-ssh':
                args.disable_remote_control = true;
                break;
            case '--help':
            case '-h':
                showHelp();
                process.exit(0);
        }
    }

    return args;
}

function getFinalConfig() {
    const cliConfig = parseArgs();
    const needEnv = !cliConfig.http_server || !cliConfig.token; 
    const envConfig = needEnv ? parseEnvArgs() : {};
    const config = {
        ...envConfig,
        ...Object.fromEntries(
          Object.entries(cliConfig).filter(
            ([_, v]) => v !== undefined && v !== null && v !== ''
          )
        )
    };
    if (!config.http_server) {
        console.error('错误: 必须提供 --http-server 参数或设置 KOMARI_HTTP_SERVER 环境变量');
        showHelp();
        process.exit(1);
    }

    if (!config.token) { 
        console.error('错误: 必须提供 --token 参数或设置 KOMARI_TOKEN 环境变量');
        showHelp();
        process.exit(1);
    }

    return config;
}

function showHelp() {
    console.log(`${SystemInfoCollector.version}\n`);
    console.log('用法: node komari-agent.js --token <token> [选项]\n');
    console.log('选项:');
    console.log('  --http-server <url>        服务器地址 (也可通过 KOMARI_HTTP_SERVER 环境变量设置) (必须)');
    console.log('  --token <token>            认证令牌 (也可通过 KOMARI_TOKEN 环境变量设置) (必须)');
    console.log('  --interval <sec>           实时数据上报间隔 (默认: 1.0秒，可通过 KOMARI_INTERVAL 环境变量设置)');
    console.log('  --log-level <level>        日志级别: 0=关闭, 1=基础信息调试, 2=websocket信息调试 (默认: 0)');
    console.log('  --disable-web-ssh          禁用远程控制功能 (远程执行和终端)');
    console.log('  --help                     显示此帮助信息');
    console.log('\n环境变量配置:');
    console.log('  所有命令行参数均可通过环境变量设置，环境变量优先级低于命令行参数。');
}

async function checkEnvironment() {
    Logger.debug('正在检查运行环境...', 6);

    const errors = [];

    // 检查 Node.js 版本
    const nodeVersion = process.version;
    const majorVersion = parseInt(process.version.slice(1).split('.')[0]);
    if (majorVersion < 14) {
        errors.push(`需要 Node.js 14.0 或更高版本，当前版本: ${nodeVersion}`);
    } else {
        Logger.debug(`✅ Node.js 版本: ${nodeVersion}`, 6);
    }

    // 检查必要模块
    const requiredModules = ['ws', 'child_process', 'os', 'fs', 'path', 'https', 'http', 'net'];
    for (const module of requiredModules) {
        try {
            require(module);
            Logger.debug(`✅ 模块 ${module} 可用`, 6);
        } catch (error) {
            errors.push(`缺少必要模块: ${module}`);
        }
    }

    // 检查系统命令
    const requiredCommands = process.platform === 'win32' ? [] : ['script', 'ping', 'df', 'python', 'python3'];
    for (const cmd of requiredCommands) {
        try {
            execSync(`which ${cmd}`);
            Logger.debug(`✅ 系统命令 ${cmd} 可用`, 6);
            commandAvailability[cmd] = true; // 标记为可用
        } catch (error) {
            const warningMessages = {
                'script': '缺少 script 命令，终端功能将使用基础模式（交互体验受限）',
                'ping': '缺少 ping 命令，网络探测功能将无法进行 ICMP 检测',
                'df': '缺少 df 命令，磁盘信息统计可能不准确',
                'python': '缺少 python 命令，终端 PTY 功能将无法使用 Python 备用方案',
                'python3': '缺少 python3 命令，终端 PTY 功能将无法使用 Python 备用方案'
            };
            
            const warning = warningMessages[cmd] || `缺少系统命令: ${cmd}`;
            Logger.warning(`⚠️  ${warning}`, 6);
            commandAvailability[cmd] = false; // 标记为不可用
        }
    }

    // 检查 /proc 文件系统 (Linux)
    if (process.platform !== 'win32') {
        try {
            fs.accessSync('/proc/stat', fs.constants.R_OK);
            Logger.debug('✅ /proc 文件系统可访问', 6);
        } catch (error) {
            errors.push('无法访问 /proc 文件系统，系统信息监控功能受限');
        }
    }

    if (errors.length > 0) {
        console.log('❌ 环境检查失败，发现以下问题:');
        errors.forEach(error => console.log(`   - ${error}`));
        return false;
    }
    Logger.debug('✅ 环境检查通过，所有依赖项均可用', 6);
    return true;
}

// 主程序
async function main() {
    try {
        const config = getFinalConfig();
        // 捕获未处理的异常
        process.on('uncaughtException', (err) => {
            Logger.error(`未捕获异常 (uncaughtException): ${err.stack || err}`);
        });

        // 捕获未处理的 Promise 拒绝
        process.on('unhandledRejection', (reason, promise) => {
            Logger.error(`未处理的 Promise 拒绝 (unhandledRejection): ${reason}`);
        });

        // 捕获进程退出
        process.on('exit', (code) => {
            Logger.info(`进程退出，退出码: ${code}`);
        });

        // 捕获被外部信号终止（如 Ctrl+C、kill）
        process.on('SIGINT', () => {
            Logger.warning('收到 SIGINT（Ctrl+C），程序即将退出');
            process.exit(130);
        });

        process.on('SIGTERM', () => {
            Logger.warning('收到 SIGTERM（系统或容器要求停止），程序即将退出');
            process.exit(143);
        });
        // 正常模式：环境检查并启动监控
        if (await checkEnvironment()) {
            Logger.setLogLevel(config.log_level);
            const client = new KomariMonitorClient(config);
            await client.run();
        } else {
            process.exit(1);
        }
    } catch (error) {
        Logger.error(`程序异常: ${error.message}`);
        process.exit(1);
    }
}
// console.log(require.main === module);
// console.log(require.main);
// console.log(module);
// console.log(require.main.filename);
// console.log(__filename);
// 启动程序

if (process.argv[1] === __filename) {
    main();
}

module.exports = {
    Logger,
    SystemInfoCollector,
    KomariWebSocketClient,
    TerminalSessionHandler,
    EventHandler,
    KomariMonitorClient,
    commandAvailability
};
