# encoding: utf-8

from setuptools import setup, find_packages

version = '1.0.0'

setup(
    name='ckanext-accesscontrol',
    version=version,
    description='An extension for CKAN providing OpenID Connect authentication and role-based access control',
    url='https://github.com/SAEONData/ckanext-accesscontrol',
    author='Mark Jacobson',
    author_email='mark@saeon.ac.za',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='CKAN OAuth2 OpenIDConnect Authentication Authorization Roles Permissions Privileges',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    namespace_packages=['ckanext'],
    install_requires=[
        # CKAN extensions should list dependencies in requirements.txt, not here
    ],
    include_package_data=True,
    package_data={},
    entry_points='''
        [ckan.plugins]
        openidconnect = ckanext.accesscontrol.openidconnect_plugin:OpenIDConnectPlugin
        roles = ckanext.accesscontrol.roles_plugin:RolesPlugin

        [paste.paster_command]
        roles = ckanext.accesscontrol.roles_command:RolesCommand

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
