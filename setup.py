from setuptools import find_packages, setup

setup(
    name='mydatabase',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask',
        # Add any other required packages here
    ],
)
