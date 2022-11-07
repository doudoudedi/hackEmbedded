from setuptools import setup




setup(name='hackebds',
      version='0.2.1',
      description='This tool is used for backdoor and shellcode generation for various architecture devices',
      long_description_content_type="text/markdown",
      long_description="https://github.com/doudoudedi/hackEmbedde",
      url='https://github.com/doudoudedi/hackEmbedded',
      author='doudoudedi',
      author_email='doudoudedi233@gmail.com',
      license='MIT',
      install_requires=[
      'pwn',
      'requests',
      'colorama',
      ],
      python_requires='>=3.6',
      py_modules=['hackebds.arm','hackebds.mips',"hackebds.aarch64","hackebds.extract_shellcode",'hackebds.model_choise','hackebds.cve_info'],
      data_files=["README.md"],
      entry_points={
      'console_scripts': [
      'hackebds = hackebds:main',
    ]
  },
)

