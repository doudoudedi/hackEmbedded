from setuptools import setup
filepath="./README.md"
readme_data=open(filepath).read()


setup(name='hackebds',
      version='0.0.9',
      description='This tool is used for backdoor and shellcode generation for various architecture devices',
      long_description=readme_data,
      long_description_content_type="text/markdown",
      url='https://github.com/doudoudedi/hackEmbedded',
      author='doudoudedi',
      author_email='doudoudedi233@gmail.com',
      license='MIT',
      py_modules=['hackebds.arm','hackebds.mips',"hackebds.aarch64","hackebds.extract_shellcode"],
      data_files=[filepath]
)

