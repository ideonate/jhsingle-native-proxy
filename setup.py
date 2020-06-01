import setuptools


with open("README.md", "r") as fh:
    long_description = fh.read()

# read requirements.txt
with open('requirements.txt', 'r') as f:
    content = f.read()
li_req = content.split('\n')
install_requires = [e.strip() for e in li_req if len(e)]

setuptools.setup(
    name="jhsingle-native-proxy",
    version="0.1.3",
    author="Dan Lester",
    author_email="dan@ideonate.com",
    description="Wrap an arbitrary webapp so it can be used in place of jupyter-singleuser in a JupyterHub setting",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ideonate/jhsingle-native-proxy",
    packages=setuptools.find_packages(),
    install_requires=install_requires,
    include_package_data=True,
    zip_safe=False,
    entry_points={"console_scripts": ["jhsingle-native-proxy = jhsingle_native_proxy.main:run"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
)


