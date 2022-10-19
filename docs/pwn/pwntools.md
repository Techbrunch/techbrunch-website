# Pwntools

https://github.com/Gallopsled/pwntools#readme

On mac M1 you need to build unicorn manually before install pwntools since GitHub CI does not support Mac M1:

````
git clone https://github.com/unicorn-engine/unicorn/
cd bindings/python
python setup.py install
python3 -m pip install --upgrade pwntools
```