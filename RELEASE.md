- To release a new version of jhsingle-native-proxy on PyPI:

Update setup.py to the new version

delete dist folder

`python setup.py sdist bdist_wheel`

`twine upload dist/*`

git add and git commit

`git tag -a X.X.X -m 'comment'`

`git push`

`git push --tags`

