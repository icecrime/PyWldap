from distutils.core import setup


setup(
    name='PyWldap',
    version='0.1.0',
    description='Python wrapper over Wldap32 Windows library',

    author='Arnaud Porterie',
    author_email='arnaud.porterie@gmail.com',
    url='https://github.com/icecrime/PyWldap',

    py_modules=['wldap'],

    classifiers=[
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
