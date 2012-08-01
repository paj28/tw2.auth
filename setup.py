import sys
from setuptools import setup, find_packages

# Required imports to avoid weird error messages in python2.7
try:
    import multiprocessing, logging
except Exception:
    pass

requires = [
    "tw2.sqla",
]

setup(
    name='tw2.auth',
    version='0.1',
    description='Authentication layer for ToscaWidgets 2',
    long_description=open('README.rst').read().split('.. split here', 1)[1],
    author='Paul Johnston',
    author_email='paj@pajhome.org.uk',
    url='http://github.com/paj28/tw2.auth',
    license='MIT',
    install_requires=requires,
    packages=find_packages(exclude=['ez_setup', 'tests']),
    namespace_packages = ['tw2'],
    zip_safe=False,
    include_package_data=True,
    test_suite = 'nose.collector',
    tests_require = [
    ],
    entry_points="""
        [tw2.widgets]
        # Register your widgets so they can be listed in the WidgetBrowser
        widgets = tw2.auth
    """,
    keywords = [
        'toscawidgets.widgets',
    ],
    classifiers = [
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Environment :: Web Environment :: ToscaWidgets',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Widget Sets',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
)
