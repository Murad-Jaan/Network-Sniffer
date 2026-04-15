from setuptools import setup, find_packages
import os

# Read README for long description
readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
if os.path.exists(readme_file):
    with open(readme_file, "r", encoding="utf-8") as fh:
        long_description = fh.read()
else:
    long_description = "Network Packet Analyzer - Professional network packet analyzer with security vulnerability detection"

setup(
    name="network-packet-analyzer",
    version="2.0.0",
    author="Network Analyzer Team",
    author_email="support@example.com",
    description="Professional network packet analyzer with security vulnerability detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/network-packet-analyzer",
    project_urls={
        "Documentation": "https://github.com/yourusername/network-packet-analyzer#readme",
        "Source": "https://github.com/yourusername/network-packet-analyzer",
        "Tracker": "https://github.com/yourusername/network-packet-analyzer/issues",
    },
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "Environment :: Console",
    ],
    python_requires=">=3.6",
    # Removed entry_points to avoid issues - use: python network_sniffer.py directly
    keywords="network sniffer packet analyzer security vulnerability detection credentials",
    include_package_data=True,
    zip_safe=False,
)
