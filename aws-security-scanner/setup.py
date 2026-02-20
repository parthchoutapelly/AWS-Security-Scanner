from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="aws-security-scanner",
    version="1.0.0",
    author="Your Name",
    description="Automated AWS security posture scanner with CIS Benchmark compliance reporting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/aws-security-scanner",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "aws-security-scanner=src.cli:cli",
        ],
    },
    include_package_data=True,
    package_data={
        "src": ["reports/templates/*.j2", "compliance/frameworks/*.json"],
    },
)
