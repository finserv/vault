from setuptools import setup


setup(
    name='finserv_vault',
    version='0.0.1',
    author='Aivars Kalvans',
    author_email='aivars.kalvans@gmail.com',
    url='',

    description='',
    long_description='',

    license='MIT License',

    # Required for AES.MODE_GCM
    install_requires=['pycryptodome'],

    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
#    test_suite='tests',
    packages=['finserv.vault'],
    zip_safe=False,
)
