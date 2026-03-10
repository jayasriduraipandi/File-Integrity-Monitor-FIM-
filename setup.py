from setuptools import setup, find_packages

setup(
    name="guardian-fim",
    version="1.0.0",
    author="Your Name",
    author_email="you@example.com",
    description="GuardianFIM - File Integrity Monitor for cybersecurity threat detection",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/GuardianFIM",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "guardianfim=guardian_fim:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
)
