from setuptools import setup, find_packages
import re

VERSIONFILE="unidns/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))


setup(
	# Application name:
	name="unidns",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/unidns",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Rudimentary async DNS client in Python",
	long_description="Rudimentary async DNS client in Python",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=(
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	install_requires=[
		'asysocks>=0.2.7',
	],
	entry_points={
		'console_scripts': [
			'unidns = unidns.examples.unidnsclient:main',
		],
	}
)