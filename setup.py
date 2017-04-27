from setuptools import setup

setup(name='Xerxes',
      version='1.0',
      description='Cybersecurity Project, Autonomous Information Collector',
      author='S.J., M.M., L.T.',
      url='https://github.com/Cybersecurity-Programming-Team-4/Xerxes/',

      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Cyber Security Programmers',
          'Topic :: Cyber Security :: Reconaissance Tool',
          'Programming Language :: Python :: 3.5',
      ],

      install_requires=[
          'pymysql',
          'Naked',
          'google-cloud',
          'google-api-python-client',
          #'StringIO'
      ],
     )