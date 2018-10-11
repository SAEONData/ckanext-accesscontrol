# encoding: utf-8

from setuptools import setup, find_packages

version = '0.2'

setup(
    name='ckanext-openidconnect',
    version=version,
    description='An extension enabling authenticated access to the CKAN API using OpenID Connect',
    url='https://github.com/SAEONData/ckanext-openidconnect',
    author='Mark Jacobson',
    author_email='mark@saeon.ac.za',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='CKAN OAuth2 OpenIDConnect',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    namespace_packages=['ckanext'],
    install_requires=[
        # CKAN extensions should list dependencies in requirements.txt, not here
    ],
    include_package_data=True,
    package_data={},
    entry_points='''
        [ckan.plugins]
        openidconnect = ckanext.openidconnect.plugin:OpenIDConnectPlugin

        [babel.extractors]
        ckan = ckan.lib.extract:extract_ckan
    ''',
    message_extractors={
        'ckanext': [
            ('**.py', 'python', None),
            ('**.js', 'javascript', None),
            ('**/templates/**.html', 'ckan', None),
        ],
    }
)
