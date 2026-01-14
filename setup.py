<<<<<<< HEAD
#!/usr/bin/env python3
"""
PyAirgeddon Setup Script
Python Wireless Security Auditing Tool
"""

from setuptools import setup, find_packages
import os

# Read long description from README if it exists
long_description = ""
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='pyairgeddon',
    version='1.0.0',
    author='PyAirgeddon Team',
    author_email='',
    description='Python Wireless Security Auditing Tool - GUI application inspired by Airgeddon',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='',
    
    # Package configuration
    py_modules=[
        'pyairgeddon',
        'pyairgeddon_core',
        'pyairgeddon_attacks',
        'pyairgeddon_cracker',
        'pyairgeddon_eviltwin'
    ],
    
    # Dependencies
    install_requires=[
        'scapy>=2.5.0',
    ],
    
    extras_require={
        'full': [
            'netifaces>=0.11.0',
        ],
    },
    
    # Python version requirement
    python_requires='>=3.8',
    
    # Entry points for command-line usage
    entry_points={
        'console_scripts': [
            'pyairgeddon=pyairgeddon:main',
        ],
    },
    
    # Classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: X11 Applications :: GTK',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Networking',
    ],
    
    # Keywords
    keywords='wireless security auditing wifi penetration-testing aircrack',
)
=======
#!/usr/bin/env python3
"""
PyAirgeddon Setup Script
Python Wireless Security Auditing Tool
"""

from setuptools import setup, find_packages
import os

# Read long description from README if it exists
long_description = ""
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
if os.path.exists(readme_path):
    with open(readme_path, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name='pyairgeddon',
    version='1.0.0',
    author='PyAirgeddon Team',
    author_email='',
    description='Python Wireless Security Auditing Tool - GUI application inspired by Airgeddon',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='',
    
    # Package configuration
    py_modules=[
        'pyairgeddon',
        'pyairgeddon_core',
        'pyairgeddon_attacks',
        'pyairgeddon_cracker',
        'pyairgeddon_eviltwin'
    ],
    
    # Dependencies
    install_requires=[
        'scapy>=2.5.0',
    ],
    
    extras_require={
        'full': [
            'netifaces>=0.11.0',
        ],
    },
    
    # Python version requirement
    python_requires='>=3.8',
    
    # Entry points for command-line usage
    entry_points={
        'console_scripts': [
            'pyairgeddon=pyairgeddon:main',
        ],
    },
    
    # Classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: X11 Applications :: GTK',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Networking',
    ],
    
    # Keywords
    keywords='wireless security auditing wifi penetration-testing aircrack',
)
>>>>>>> 7a1df55f49f3097f4e39d6a09d98fe1482ca394e
