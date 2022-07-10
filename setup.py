from setuptools import setup, find_packages

setup(
    name='firewall-updater',
    version='0.1',
    url='https://github.com/HQJaTu/',
    license='GPLv2',
    author='Jari Turkia',
    author_email='jatu@hqcodeshop.fi',
    description='Utilities to update firewall rules',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',

        # Specify the Python versions you support here.
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9'
        'Programming Language :: Python :: 3.10'
    ],
    python_requires='>=3.8, <4',
    install_requires=[
        'lxml',
        'dbus-python==1.2.18',
        'systemd==0.16.1',
        'systemd-watchdog==0.9.0',
        'asyncio_glib',
        'asyncio-periodic'
    ],
    scripts=['cli-utils/firewall-updater-service.py'],
    data_files=[
        ('xml-schemas', ['xml/service.xsd', 'xml/user_rule.xsd'])
    ],
    packages=find_packages()
)
