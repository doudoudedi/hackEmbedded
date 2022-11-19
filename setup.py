'''
fix CVE-2022-40023,CVE-2021-20270,Path Crossing
'''

from setuptools import setup

with open("./README.rst",'r') as f:
	data= f.read()

	


setup(name='hackebds',
      version='0.2.3',
      description='This tool is used for backdoor and shellcode generation for various architecture devices',
      long_description_content_type="text/markdown",
      long_description=data,
      url='https://github.com/doudoudedi/hackEmbedded',
      author='doudoudedi',
      author_email='doudoudedi233@gmail.com',
      license='MIT',
      install_requires=[
      'pwn',
      'requests',
      'colorama',
      'mako == 1.2.2',
      'pygments == 2.7.4',
      ],
      python_requires='>=3.6',
      py_modules=['hackebds.arm','hackebds.mips',"hackebds.aarch64","hackebds.extract_shellcode",'hackebds.model_choise','hackebds.cve_info','hackebds.powerpc_info','hackebds.ESH'],
      data_files=["README.md"],
      entry_points={
      'console_scripts': [
      'hackebds = hackebds:main',
    ]
  },
)

