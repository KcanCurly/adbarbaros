from setuptools import setup, find_packages

setup(
    name="adbarbaros",
    version="1.0.0",
    author="KcanCurly",
    description="AD stuff.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/KcanCurly/adbarbaros",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "ldap3 @ git+https://github.com/cannatag/ldap3",
        "cryptography",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.12",
    entry_points={
        "console_scripts": [
            "adbarbaros=src.main:main",  
            "adb=src.main:main",  
        ],
    },
)