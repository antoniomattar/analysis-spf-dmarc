"""
Setup configuration for SPF & DMARC Security Analyzer
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("config/requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip()
                    and not line.startswith("#")]

setup(
    name="spf-dmarc-analyzer",
    version="2.0.0",
    author="Security Research Team",
    author_email="antonio.mattar@ensimag.fr",
    description="Comprehensive SPF & DMARC security analyzer with attack detection",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/antoniomattar/analysis-spf-dmarc",
    project_urls={
        "Bug Tracker": "https://github.com/antoniomattar/analysis-spf-dmarc/issues",
        "Documentation": "https://github.com/antoniomattar/analysis-spf-dmarc/tree/main/docs",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Education",
        "Topic :: Security",
        "Topic :: Internet :: Name Service (DNS)",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "."},
    packages=find_packages(where="."),
    python_requires=">=3.11",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "spf-dmarc-analyze=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
