# setup.py
from setuptools import setup, find_packages

setup(
    name="pyagent",
    version="1.1",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "websockets", 
        "psutil",
        "click"
    ],
    entry_points={
        "console_scripts": [
            # 👇 指向同步的 entry_point 函数，不是 async 的 main
            "pyagent=py.agent:entry_point",
        ],
    },
    python_requires=">=3.8",
)