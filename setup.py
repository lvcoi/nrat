from setuptools import setup, find_packages

setup(
    name='nrat',
    version='0.1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'nrat=nrat.main:main',
        ],
    },
    install_requires=[
        'scapy',
        # Any other dependencies
    ],
    description='Network Recon & Analysis Tool',
    author='phive151',
    author_email='phive151@pm.me',
    license='MIT',
    keywords='network recon analysis',
    url='https://github.com/lvcoi/nrat',
)