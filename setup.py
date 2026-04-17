from setuptools import find_packages, setup

setup(
    name="safedev",
    version="1.0.0",
    description="Universal developer security tool for scanning packages and repositories before use",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "safedev": [
            "rules/*.json",
            "ui/*.py",
        ],
    },
    entry_points={
        "console_scripts": [
            "safedev=safedev.cli:cli",
        ],
    },
    install_requires=[
        "click>=8.0",
        "colorama>=0.4",
        "streamlit>=1.28",
        "pandas>=1.5",
        "reportlab>=4.0",
    ],
    python_requires=">=3.8",
)
